#!/usr/bin/env python3
"""A fake shim, console and cluster for probe/aws-shim-iam-login-profile.sh's self-test
(probe/test_iam_probes.py). Installed as `aws`, `kubectl` and `curl` on PATH, it keeps one JSON state file
($FAKE_STATE) and answers the calls the probe makes the way the real ones do. $FAKE_MODE breaks one
behaviour, so a test can show the probe catches it:

  good               — faithful
  wrong-old-accepted — ChangePassword ignores the old password
  console-ns         — the hash lands in the console namespace
  no-guard           — the admission guard is not installed
  iam-not-deciding   — a granted iam:ChangePassword never takes effect, and IAM policy does not decide

Every call is appended to $FAKE_STATE.log, so a test can check what the probe cleaned up.
"""
import json
import os
import sys

STATE = os.environ["FAKE_STATE"]
MODE = os.environ.get("FAKE_MODE", "good")
SHIM_NS, USERS_NS = "open-infra-aws-shim", "open-infra-console"


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"users": {}, "keys": {}, "profiles": {}, "secrets": {}}


def save(s):
    with open(STATE, "w") as f:
        json.dump(s, f)


def flags(args, valued):
    """Split args into positionals and {flag: value} (valued flags take the next arg; --k=v also works)."""
    pos, fl, i = [], {}, 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if "=" in a and a.startswith("--"):
                k, v = a.split("=", 1)
                fl.setdefault(k, []).append(v)
            elif a in valued:
                fl.setdefault(a, []).append(args[i + 1])
                i += 1
            else:
                fl.setdefault(a, []).append("")
        else:
            pos.append(a)
        i += 1
    return pos, fl


# --- aws ---------------------------------------------------------------------------------------------

def aws_error(code, op, msg="fake"):
    sys.stderr.write(f"\nAn error occurred ({code}) when calling the {op} operation: {msg}\n")
    sys.exit(254)


def aws(args):
    s = load()
    pos, fl = flags(args, {"--endpoint-url", "--output", "--user-name", "--password", "--old-password", "--new-password"})
    service, op = pos[0], pos[1]
    caller = s["keys"].get(os.environ.get("AWS_ACCESS_KEY_ID", ""))
    if caller is None:
        aws_error("InvalidClientTokenId", op)
    user = fl.get("--user-name", [""])[0]
    opname = "".join(p.capitalize() for p in op.split("-"))
    if service == "sts" and op == "get-caller-identity":
        print(json.dumps({"Arn": f"arn:aws:iam::000000000000:user/{caller}", "Account": "000000000000"}))
        return
    admin = "admins" in s["users"].get(caller, {}).get("groups", [])
    if op in ("get-login-profile", "create-login-profile", "update-login-profile", "delete-login-profile") and not admin:
        aws_error("AccessDenied", opname)
    if op == "get-account-password-policy":
        aws_error("NoSuchEntity", opname, "The Password Policy with domain name 000000000000 cannot be found.")
    if op in ("create-login-profile", "update-login-profile", "get-login-profile", "delete-login-profile"):
        if user == "root" or user not in s["users"]:
            aws_error("NoSuchEntity", opname, f"The user with name {user} cannot be found.")
        prof = s["profiles"].get(user)
        if op == "get-login-profile":
            if not prof:
                aws_error("NoSuchEntity", opname)
            print(json.dumps({"LoginProfile": {"UserName": user, "CreateDate": "2026-11-05T00:00:00Z",
                                               "PasswordResetRequired": prof["reset"]}}))
            return
        if op == "delete-login-profile":
            if not prof:
                aws_error("NoSuchEntity", opname)
            del s["profiles"][user]
            s["secrets"].pop(s["users"][user].pop("ref", ""), None)
            save(s)
            return
        pw = fl.get("--password", [""])[0]
        if op == "create-login-profile" and prof:
            aws_error("EntityAlreadyExists", opname)
        if op == "update-login-profile" and not prof:
            aws_error("NoSuchEntity", opname)
        if len(pw) < 8:
            aws_error("PasswordPolicyViolation", opname)
        reset = "--password-reset-required" in fl
        s["profiles"][user] = {"password": pw, "reset": reset}
        ns = USERS_NS if MODE == "console-ns" else SHIM_NS
        ref = f"{ns}/iam-login-{user}-0123456789"
        s["users"][user]["ref"] = ref
        s["secrets"][ref] = {"openinfra.dev/login-profile": "true", "openinfra.dev/iam-user": user}
        save(s)
        print(json.dumps({"LoginProfile": {"UserName": user, "CreateDate": "2026-11-05T00:00:00Z",
                                           "PasswordResetRequired": reset}}))
        return
    if op == "change-password":
        granted = s["users"][caller].get("granted") and MODE != "iam-not-deciding"
        if not granted:
            aws_error("AccessDenied", "ChangePassword")
        prof = s["profiles"].get(caller)
        if not prof:
            aws_error("NoSuchEntity", "ChangePassword")
        if fl["--old-password"][0] != prof["password"] and MODE != "wrong-old-accepted":
            aws_error("InvalidUserType", "ChangePassword", "The specified value for oldPassword is invalid.")
        prof.update(password=fl["--new-password"][0], reset=False)
        save(s)
        return
    aws_error("InvalidAction", opname)


# --- kubectl -----------------------------------------------------------------------------------------

def kubectl(args):
    s = load()
    pos, fl = flags(args, {"-n", "-o", "-f", "--type", "--patch-file"})
    ns = fl.get("-n", [""])[0]
    verb = pos[0]
    if verb == "apply":
        with open(fl["-f"][0]) as f:
            obj = json.load(f)
        s["users"][obj["metadata"]["name"]] = {"groups": obj["spec"]["groups"]}
        save(s)
        return
    if verb == "delete":
        return
    if verb == "create" and pos[1:3] == ["secret", "generic"]:
        name = pos[3]
        lit = dict(v.split("=", 1) for v in fl.get("--from-literal", []))
        if "--dry-run" in fl:
            shim = "system:serviceaccount:open-infra-aws-shim:aws-shim" in fl.get("--as", [])
            if shim and name.startswith("iam-login-") and MODE != "no-guard":
                sys.stderr.write(f'The secrets "{name}" is invalid: : ValidatingAdmissionPolicy '
                                 "'openinfra-login-profile-guard' with binding 'openinfra-login-profile-guard' denied "
                                 'request: a login profile is a Secret named iam-login-* labelled '
                                 'openinfra.dev/login-profile: "true", both or neither\n')
                sys.exit(1)
            print(f"secret/{name}")
            return
        if name.startswith("iam-ak-"):
            s["keys"][lit["accessKeyId"]] = lit["owner"]
        save(s)
        return
    if verb == "get" and pos[1] == "users.iam.openinfra.dev":
        print(s["users"][pos[2]].get("ref", ""), end="")
        return
    if verb == "get" and pos[1] == "secret":
        labels = s["secrets"].get(f"{ns}/{pos[2]}")
        if labels is None:
            sys.exit(1)
        if "-o" in fl:
            print(f'{labels["openinfra.dev/login-profile"]} {labels["openinfra.dev/iam-user"]}', end="")
        return
    if verb == "patch":
        with open(fl["--patch-file"][0]) as f:
            patch = json.load(f)
        if patch["spec"]["inlinePolicies"][0]["document"]["Statement"][0]["Action"] == "iam:ChangePassword":
            s["users"][pos[2]]["granted"] = True
        save(s)
        return
    sys.stderr.write(f"fake kubectl: unhandled {args}\n")
    sys.exit(2)


# --- curl (the console) ------------------------------------------------------------------------------

def curl(args):
    s = load()
    pos, fl = flags(args, {"-m", "-c", "-b", "-o", "-w", "-H", "-d"})
    url = pos[-1]
    path = url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else ""
    path = "/" + path
    if path == "/healthz":
        return
    body = json.loads(fl["-d"][0]) if "-d" in fl else None
    session = None
    if "-b" in fl and os.path.exists(fl["-b"][0]):
        with open(fl["-b"][0]) as f:
            session = json.load(f)

    def answer(code, obj, cookie=None):
        if cookie is not None and "-c" in fl:
            with open(fl["-c"][0], "w") as f:
                json.dump(cookie, f)
        text = json.dumps(obj)
        if "-o" in fl:
            with open(fl["-o"][0], "w") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        if "-w" in fl:
            sys.stdout.write(str(code))

    if path == "/api/auth/login":
        u, prof = body["Username"], s["profiles"].get(body["Username"])
        if not prof or prof["password"] != body["Password"]:
            return answer(401, {"error": "invalid username or password"})
        return answer(200, {"user": u, "role": "user", "passwordResetRequired": prof["reset"]},
                      {"user": u, "reset": prof["reset"]})
    if session is None:
        return answer(401, {"error": "not signed in"})
    if path == "/api/auth/me":
        return answer(200, {"user": session["user"], "iamAuthz": "legacy" if MODE == "iam-not-deciding" else "enforce"})
    if path == "/api/auth/change-password":
        prof = s["profiles"][session["user"]]
        if body["oldPassword"] != prof["password"]:
            return answer(400, {"code": "InvalidUserType"})
        prof.update(password=body["newPassword"], reset=False)
        save(s)
        return answer(200, {"ok": True}, {"user": session["user"], "reset": False})
    if session.get("reset"):
        return answer(403, {"code": "PasswordResetRequired"})
    return answer(200, {})


if __name__ == "__main__":
    tool = sys.argv[1]
    with open(STATE + ".log", "a") as f:
        f.write(json.dumps([tool] + sys.argv[2:]) + "\n")
    {"aws": aws, "kubectl": kubectl, "curl": curl}[tool](sys.argv[2:])
