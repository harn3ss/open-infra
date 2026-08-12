#!/usr/bin/env python3
"""Generate the open-infra Platform API OpenAPI 3 spec from the CRD schemas.

GovStack building blocks must expose OpenAPI-described interfaces (Architecture Blueprint). The
DECLARATIVE resource API — the openinfra.dev CRDs a block provisions infrastructure through — is
open-infra's meaningful "platform API", and its schemas already live in platform/abstraction/*-xrd.yaml
(the single source of truth). This walks those XRDs and emits one OpenAPI 3.0 document: a component
schema per user-facing kind (from the XRD spec/status schema) and the Kubernetes resource paths
(list/create/get/delete) for each. Generated — never hand-edit the output; re-run to refresh.

  docs/openapi/generate.py            # write docs/openapi/openinfra-platform.openapi.yaml
  docs/openapi/generate.py --check    # fail if the committed spec is stale (CI drift gate)
"""
import glob
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ABSTRACTION = os.path.normpath(os.path.join(HERE, "..", "..", "platform", "abstraction"))
OUT = os.path.join(HERE, "openinfra-platform.openapi.yaml")


def load_kinds():
    kinds = []
    for path in sorted(glob.glob(os.path.join(ABSTRACTION, "*xrd*.yaml")) +
                       glob.glob(os.path.join(ABSTRACTION, "xrd.yaml"))):
        d = yaml.safe_load(open(path, encoding="utf-8"))
        if not d or d.get("kind") != "CompositeResourceDefinition":
            continue
        spec = d["spec"]
        claim = spec.get("claimNames")
        if not claim:  # composite-only (no user-facing claim) — skip
            continue
        ver = spec["versions"][0]
        schema = ver["schema"]["openAPIV3Schema"].get("properties", {})
        kinds.append({
            "kind": claim["kind"],
            "plural": claim["plural"],
            "group": spec["group"],
            "version": ver["name"],
            "spec": schema.get("spec", {"type": "object"}),
            "status": schema.get("status"),
        })
    # de-dupe by kind (xrd.yaml == Application), keep first
    seen, out = set(), []
    for k in kinds:
        if k["kind"] in seen:
            continue
        seen.add(k["kind"])
        out.append(k)
    return sorted(out, key=lambda k: k["kind"])


def build_spec(kinds):
    schemas = {
        "ObjectMeta": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Resource name (RFC 1123)."},
                "namespace": {"type": "string"},
                "labels": {"type": "object", "additionalProperties": {"type": "string"}},
                "annotations": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
        "Status": {"type": "object", "description": "K8s API status on error.",
                   "properties": {"message": {"type": "string"}, "reason": {"type": "string"},
                                  "code": {"type": "integer"}}},
    }
    paths = {}
    for k in kinds:
        comp = {
            "type": "object",
            "description": f"open-infra kind: {k['kind']}.",
            "required": ["spec"],
            "properties": {
                "apiVersion": {"type": "string", "enum": [f"{k['group']}/{k['version']}"]},
                "kind": {"type": "string", "enum": [k["kind"]]},
                "metadata": {"$ref": "#/components/schemas/ObjectMeta"},
                "spec": k["spec"],
            },
        }
        if k["status"]:
            comp["properties"]["status"] = k["status"]
        schemas[k["kind"]] = comp

        ref = {"$ref": f"#/components/schemas/{k['kind']}"}
        listp = f"/namespaces/{{namespace}}/{k['plural']}"
        itemp = listp + "/{name}"
        ns_param = {"name": "namespace", "in": "path", "required": True, "schema": {"type": "string"}}
        name_param = {"name": "name", "in": "path", "required": True, "schema": {"type": "string"}}
        paths[listp] = {
            "get": {"tags": [k["kind"]], "summary": f"List {k['kind']} resources", "parameters": [ns_param],
                    "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {
                        "type": "object", "properties": {"items": {"type": "array", "items": ref}}}}}}}},
            "post": {"tags": [k["kind"]], "summary": f"Create a {k['kind']}", "parameters": [ns_param],
                     "requestBody": {"required": True, "content": {"application/json": {"schema": ref}}},
                     "responses": {"201": {"description": "Created", "content": {"application/json": {"schema": ref}}},
                                   "409": {"description": "Already exists",
                                           "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Status"}}}}}},
        }
        paths[itemp] = {
            "get": {"tags": [k["kind"]], "summary": f"Get a {k['kind']}", "parameters": [ns_param, name_param],
                    "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": ref}}},
                                  "404": {"description": "Not found",
                                          "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Status"}}}}}},
            "delete": {"tags": [k["kind"]], "summary": f"Delete a {k['kind']}", "parameters": [ns_param, name_param],
                       "responses": {"200": {"description": "Deleted"}, "404": {"description": "Not found"}}},
        }

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "open-infra Platform API",
            "version": "v1",
            "description": (
                "The declarative resource API a GovStack building block provisions infrastructure through. "
                "Every path is a standard Kubernetes resource endpoint under the openinfra.dev group; the "
                "schemas are GENERATED from platform/abstraction/*-xrd.yaml (the CRD source of truth), so "
                "this spec can never drift from the running API. GENERATED — do not hand-edit."
            ),
            "x-openinfra-kinds": len(kinds),
        },
        "servers": [{"url": "/apis/openinfra.dev/v1", "description": "Kubernetes API server (openinfra.dev group)"}],
        "tags": [{"name": k["kind"]} for k in kinds],
        "paths": paths,
        "components": {"schemas": schemas},
    }


def main():
    kinds = load_kinds()
    spec = build_spec(kinds)
    text = "# GENERATED by docs/openapi/generate.py from platform/abstraction/*-xrd.yaml — do not edit.\n" + \
        yaml.safe_dump(spec, sort_keys=False, width=120)
    if "--check" in sys.argv:
        cur = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if cur != text:
            print("FAIL: docs/openapi/openinfra-platform.openapi.yaml is STALE — run docs/openapi/generate.py")
            return 1
        print(f"OK: platform OpenAPI spec is current ({len(kinds)} kinds).")
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {OUT} — {len(kinds)} kinds, {len(spec['paths'])} paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
