#!/usr/bin/env python3
"""Move the platform's keys from Vault (the encryption component) to OpenBao, by storage copy.

Runs in the openbao-move pod (scripts/vault-to-openbao.sh prepare), in two parts the operator starts:

  run     Reads the operator's credentials from stdin, as NAME=value lines piped from where they keep them:
          VAULT_ROOT_TOKEN, three of Vault's unseal keys (VAULT_UNSEAL_KEY_<n>) and OPENBAO_ROOT_TOKEN (the
          root token OpenBao's own initialization printed). Then:
            1. checks every precondition, and stops before changing anything if one fails;
            2. seals Vault, so its storage is still while it is copied (the keys are unavailable from here
               until the clients use OpenBao);
            3. copies Vault's storage into this pod and converts it to Raft with Vault's own
               `vault operator migrate` (OpenBao reads Raft, not Vault's file storage);
            4. opens the copy in a temporary OpenBao and moves its seal from Vault's unseal keys to the
               unseal host's key (the keys become the copy's recovery keys);
            5. generates a temporary root token with them, replaces them with three new recovery keys, and
               checks every key version round-trips;
            6. force-restores the copy into the OpenBao cluster, restarts its members (they unseal
               themselves through the unseal host) and checks every key version again there;
            7. revokes every other root token the copy carried (Vault's among them).
          If a step fails before the restore, Vault is unsealed again and nothing has changed. If it fails
          after, Vault is unsealed again too; OpenBao keeps the copy, and the clients still use Vault.
  finish  Interactive. Shows the new recovery keys `run` made (three, any two of which authorize recovery,
          replacing Vault's unseal keys in that role), waits until the operator confirms they are stored,
          then revokes the temporary root token.

No key, token or value is printed except the new recovery keys in `finish`, which go to the operator's
terminal alone. What the two parts share (the temporary token, the new recovery keys) lives in a
memory-backed volume of this pod, deleted with it. A status file without secrets (/run/move/status.json)
lets the operator, or an agent helping them, follow progress.
"""
import base64, calendar, hashlib, json, os, re, shutil, ssl, subprocess, sys, time, urllib.error, urllib.request

E = os.environ.get
VAULT = E("MOVE_VAULT_ADDR", "http://vault.vault.svc.cluster.local:8200")
LIVE = E("MOVE_LIVE_ADDR", "https://openbao-active.openbao.svc:8200")
LIVE_CA = E("MOVE_LIVE_CACERT", "/etc/openbao-ca/ca.crt")
TEMP = E("MOVE_TEMP_ADDR", "http://127.0.0.1:8210")
WORK = E("MOVE_WORK", "/work")
STASH = E("MOVE_STASH", "/run/move")
TOOLS = E("MOVE_TOOLS", "/tools")
CFG = E("MOVE_CFG", "/cfg")
COPY_CMD = E("MOVE_COPY_CMD", "kubectl -n vault exec vault-0 -c vault -- tar -C /vault/data -cf - .")
RESTART_CMD = E("MOVE_RESTART_CMD", "kubectl -n openbao delete pod openbao-0 openbao-1 openbao-2 --wait=false")
MEMBERS_CMD = E("MOVE_MEMBERS_CMD", "kubectl -n openbao get pods -l app.kubernetes.io/name=openbao,component=server -o json")
PREFLIGHT_CMD = E("MOVE_PREFLIGHT_CMD", "kubectl -n vault exec vault-0 -c vault -- true")
PROBE = base64.b64encode(b"vault-to-openbao-probe").decode()
CONTEXT = base64.b64encode(b"vault-to-openbao").decode()
T0 = time.time()
STATUS = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": []}


def now():
    return "%5.0fs" % (time.time() - T0)


def status(step, state, **kw):
    STATUS["steps"].append(dict(step=step, state=state, at=round(time.time() - T0), **kw))
    os.makedirs(STASH, exist_ok=True)
    with open(os.path.join(STASH, "status.json"), "w") as f:
        json.dump(STATUS, f)


def say(msg):
    print("%s  %s" % (now(), msg), flush=True)


class Fail(Exception):
    pass


def call(addr, method, path, body=None, token=None, raw=None, ca=None, timeout=60, want_raw=False):
    headers = {}
    data = None
    if raw is not None:
        data, headers["Content-Type"] = raw, "application/octet-stream"
    elif body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    if token:
        headers["X-Vault-Token"] = token
    ctx = ssl.create_default_context(cafile=ca) if (addr.startswith("https") and ca) else None
    url = addr + "/v1/" + path
    for _ in range(3):   # a standby may answer 307 to the active member (right after a restart)
        req = urllib.request.Request(url, method=method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                out = r.read()
                if want_raw:
                    return out
                return json.loads(out) if out else {}
        except urllib.error.HTTPError as e:
            if e.code != 307 or not e.headers.get("Location"):
                raise
            url = e.headers["Location"]
    raise Fail("too many redirects for " + path)


def err_text(e):
    try:
        return "; ".join(json.loads(e.read() or b"{}").get("errors", [])) or "HTTP %d" % e.code
    except Exception:  # noqa: BLE001
        return "HTTP %d" % getattr(e, "code", 0)


def clean(v):
    v = v.strip()
    if v.startswith("export "):
        v = v[7:].strip()
    return v.strip("'\"").strip()


def read_inputs():
    vals, keys = {}, []
    for line in sys.stdin:
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].strip()
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            continue
        name, v = m.group(1), clean(m.group(2))
        if re.match(r"^VAULT_UNSEAL_KEY_\d+$", name):
            if v and v not in keys:
                keys.append(v)
        elif name in ("VAULT_ROOT_TOKEN", "OPENBAO_ROOT_TOKEN"):
            vals[name] = v
    missing = [n for n in ("VAULT_ROOT_TOKEN", "OPENBAO_ROOT_TOKEN") if not vals.get(n)]
    if missing:
        raise Fail("missing on stdin: " + ", ".join(missing))
    if not keys:
        raise Fail("no VAULT_UNSEAL_KEY_<n> line on stdin")
    return vals["VAULT_ROOT_TOKEN"], keys, vals["OPENBAO_ROOT_TOKEN"]


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True, **kw).stdout


def members(since=0):
    """(member pods, of them Ready and created after `since`): a restart counts only fresh pods."""
    pods = json.loads(sh(MEMBERS_CMD))["items"]
    ready = [p for p in pods
             if not p["metadata"].get("deletionTimestamp")
             and calendar.timegm(time.strptime(p["metadata"]["creationTimestamp"], "%Y-%m-%dT%H:%M:%SZ")) >= since
             and any(c["type"] == "Ready" and c["status"] == "True" for c in p.get("status", {}).get("conditions", []))]
    return len(pods), len(ready)


def wait(what, fn, seconds):
    end = time.time() + seconds
    last = None
    while time.time() < end:
        try:
            if fn():
                return
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(2)
    raise Fail("%s: not within %ds%s" % (what, seconds, (" (%s)" % last) if last else ""))


def wait_stable_leader(seconds=300, settle=5):
    """After the restore and restart: a leader that is a member (the copy carries the temporary node's
    announcement until a member replaces it) and the same one for `settle` checks in a row."""
    temp_host = TEMP.split("//", 1)[-1]
    seen, same = None, 0
    end = time.time() + seconds
    while time.time() < end:
        try:
            d = call(LIVE, "GET", "sys/leader", ca=LIVE_CA)
            la = d.get("leader_address") or ""
            if d.get("ha_enabled") and la and temp_host not in la:
                same = same + 1 if la == seen else 1
                seen = la
                if same >= settle:
                    return
            else:
                seen, same = None, 0
        except Exception:  # noqa: BLE001
            seen, same = None, 0
        time.sleep(2)
    raise Fail("the cluster did not settle on a leader within %ds" % seconds)


def retry(fn, tries=5):
    for i in range(tries):
        try:
            return fn()
        except (urllib.error.URLError, OSError):
            if i == tries - 1:
                raise
            time.sleep(3)


def unseal_with(addr, keys, migrate=False):
    st = {}
    call(addr, "PUT", "sys/unseal", {"reset": True})
    for k in keys:
        body = {"key": k}
        if migrate:
            body["migrate"] = True
        st = call(addr, "PUT", "sys/unseal", body)
        if not st.get("sealed"):
            return st
    return st


def check_keys(addr, token, ca=None):
    """Round-trip every version of every Transit key; return (counts, failures). Prints nothing secret."""
    counts, fails = {"transit keys": 0, "key versions round-tripped": 0, "signing keys sign+verify": 0}, []
    for mpath, m in call(addr, "GET", "sys/mounts", token=token, ca=ca)["data"].items():
        if m["type"] != "transit":
            continue
        try:
            names = call(addr, "LIST", mpath + "keys", token=token, ca=ca)["data"]["keys"]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            raise
        for name in names:
            info = call(addr, "GET", mpath + "keys/" + name, token=token, ca=ca)["data"]
            counts["transit keys"] += 1
            ctx = {"context": CONTEXT} if info.get("derived") else {}
            tag = hashlib.sha256(name.encode()).hexdigest()[:8]
            if info.get("supports_encryption"):
                lo = max(info.get("min_decryption_version", 1), info.get("min_encryption_version", 0) or 1)
                for v in range(lo, info["latest_version"] + 1):
                    try:
                        ct = call(addr, "POST", mpath + "encrypt/" + name, dict(plaintext=PROBE, key_version=v, **ctx), token=token, ca=ca)["data"]["ciphertext"]
                        if call(addr, "POST", mpath + "decrypt/" + name, dict(ciphertext=ct, **ctx), token=token, ca=ca)["data"]["plaintext"] == PROBE:
                            counts["key versions round-tripped"] += 1
                        else:
                            fails.append("%s v%d: wrong plaintext" % (tag, v))
                    except urllib.error.HTTPError as e:
                        fails.append("%s v%d: %s" % (tag, v, err_text(e)))
            if info.get("supports_signing"):
                try:
                    sig = call(addr, "POST", mpath + "sign/" + name, dict(input=PROBE, **ctx), token=token, ca=ca)["data"]["signature"]
                    if call(addr, "POST", mpath + "verify/" + name, dict(input=PROBE, signature=sig, **ctx), token=token, ca=ca)["data"]["valid"]:
                        counts["signing keys sign+verify"] += 1
                    else:
                        fails.append("%s: signature invalid" % tag)
                except urllib.error.HTTPError as e:
                    fails.append("%s sign: %s" % (tag, err_text(e)))
    return counts, fails


def stash_write(name, value):
    os.makedirs(STASH, mode=0o700, exist_ok=True)
    path = os.path.join(STASH, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)


def stash_read(name):
    with open(os.path.join(STASH, name)) as f:
        return f.read()


def run():
    vault_root, keys, live_root = read_inputs()
    say("read the credentials from stdin (%d unseal keys); none is shown" % len(keys))
    status("inputs", "ok", unseal_keys=len(keys))
    temp = None
    sealed_vault = False
    restored = False
    try:
        # 1. Preconditions.
        vs = call(VAULT, "GET", "sys/seal-status")
        if vs.get("sealed"):
            raise Fail("Vault is sealed already: unseal it first (nothing changed)")
        if len(keys) < vs["t"]:
            raise Fail("Vault needs %d unseal keys, %d given" % (vs["t"], len(keys)))
        keys = keys[: vs["t"]]
        if "root" not in call(VAULT, "GET", "auth/token/lookup-self", token=vault_root)["data"]["policies"]:
            raise Fail("VAULT_ROOT_TOKEN is not a root token")
        try:
            pol = call(LIVE, "GET", "auth/token/lookup-self", token=live_root, ca=LIVE_CA)["data"]["policies"]
        except urllib.error.HTTPError as e:
            raise Fail("OPENBAO_ROOT_TOKEN was refused by OpenBao (%s)" % err_text(e))
        if "root" not in pol:
            raise Fail("OPENBAO_ROOT_TOKEN is not a root token")
        n, r = members()
        if (n, r) != (3, 3):
            raise Fail("OpenBao has %d members, %d ready: need 3 and 3" % (n, r))
        for d in ("file", "raft"):
            shutil.rmtree(os.path.join(WORK, d), ignore_errors=True)
            os.makedirs(os.path.join(WORK, d))
        sh(PREFLIGHT_CMD)   # this pod may read Vault's storage
        say("preconditions hold: Vault unsealed (%d of %d keys), both root tokens valid, OpenBao 3/3 ready" % (vs["t"], vs["n"]))
        status("preconditions", "ok", vault_threshold=vs["t"], vault_shares=vs["n"])

        # 2. Seal Vault: from here the keys are unavailable until the clients use OpenBao.
        call(VAULT, "PUT", "sys/seal", token=vault_root)
        sealed_vault = True
        say("Vault sealed: the window starts (KMS, Secrets Manager and key creation are unavailable)")
        status("vault-sealed", "ok")

        # 3. Copy and convert.
        cp = subprocess.Popen(COPY_CMD, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tar = subprocess.run(["tar", "-C", os.path.join(WORK, "file"), "-xf", "-"], stdin=cp.stdout, capture_output=True)
        cp.stdout.close()
        if cp.wait() != 0 or tar.returncode != 0:
            raise Fail("copying Vault's storage failed: %s" % ((cp.stderr.read().decode() or tar.stderr.decode())[-300:]))
        files = sum(len(f) for _, _, f in os.walk(os.path.join(WORK, "file")))
        say("copied Vault's storage (%d files)" % files)
        mig = subprocess.run([os.path.join(TOOLS, "vault"), "operator", "migrate", "-config=" + os.path.join(CFG, "migrate.hcl")],
                             capture_output=True, text=True)
        if mig.returncode != 0 or "Success" not in mig.stdout + mig.stderr:
            raise Fail("vault operator migrate failed: %s" % (mig.stderr or mig.stdout)[-300:])
        copied = (mig.stdout + mig.stderr).count("copied key")
        say("converted it to Raft with Vault's own migrate (%d storage entries)" % copied)
        status("copied", "ok", files=files, entries=copied)

        # 4. Open the copy and move its seal to the unseal host's key.
        env = dict(os.environ, BAO_TOKEN=E("MOVE_SEAL_TOKEN", ""), HOME=os.path.join(WORK, "home"))
        os.makedirs(env["HOME"], exist_ok=True)
        log = open(os.path.join(WORK, "temp-node.log"), "w")
        temp = subprocess.Popen([os.path.join(TOOLS, "bao"), "server", "-config=" + os.path.join(CFG, "temp-node.hcl")],
                                env=env, stdout=log, stderr=subprocess.STDOUT)
        wait("the temporary OpenBao to answer", lambda: call(TEMP, "GET", "sys/seal-status").get("initialized"), 90)
        st = call(TEMP, "GET", "sys/seal-status")
        if not st.get("migration"):
            raise Fail("the copy did not enter seal migration (seal %s)" % st.get("type"))
        st = unseal_with(TEMP, keys, migrate=True)
        if st.get("sealed"):
            raise Fail("Vault's unseal keys did not open the copy")
        wait("the copy to become active", lambda: call(TEMP, "GET", "sys/leader").get("is_self"), 120)
        st = call(TEMP, "GET", "sys/seal-status")
        say("the copy is open, its seal moved to the unseal host (%s); Vault's keys are its recovery keys" % st.get("type"))
        status("seal-migrated", "ok", seal=st.get("type"))

        # 5. Temporary root token, then every key version.
        call(TEMP, "DELETE", "sys/generate-root/attempt")
        att = call(TEMP, "PUT", "sys/generate-root/attempt", {})
        res = {}
        for k in keys:
            res = call(TEMP, "PUT", "sys/generate-root/update", {"key": k, "nonce": att["nonce"]})
        enc = res.get("encoded_token") or res.get("encoded_root_token") or ""
        enc += "=" * (-len(enc) % 4)
        enc = base64.urlsafe_b64decode(enc) if ("-" in enc or "_" in enc) else base64.b64decode(enc)
        token = bytes(a ^ b for a, b in zip(enc, att["otp"].encode())).decode()
        stash_write("t", token)
        # New recovery keys, before the snapshot, so the cluster receives them with the copy. (OpenBao's
        # rekey endpoints are off on the cluster's listeners; this temporary node turns them on.)
        call(TEMP, "DELETE", "sys/rekey-recovery-key/init")
        init = call(TEMP, "PUT", "sys/rekey-recovery-key/init", {"secret_shares": 3, "secret_threshold": 2})
        res = {}
        for k in keys:
            res = call(TEMP, "PUT", "sys/rekey-recovery-key/update", {"key": k, "nonce": init["nonce"]})
            if res.get("complete"):
                break
        new_keys = res.get("keys_base64") or res.get("keys") or []
        if not res.get("complete") or len(new_keys) != 3:
            raise Fail("replacing the recovery keys did not complete")
        stash_write("rk", "\n".join(new_keys))
        # Prove two of the new keys authorize recovery: mint a root token with them, then revoke it.
        call(TEMP, "DELETE", "sys/generate-root/attempt")
        att2 = call(TEMP, "PUT", "sys/generate-root/attempt", {})
        res2 = {}
        for k in new_keys[:2]:
            res2 = call(TEMP, "PUT", "sys/generate-root/update", {"key": k, "nonce": att2["nonce"]})
        enc2 = res2.get("encoded_token") or res2.get("encoded_root_token") or ""
        if not res2.get("complete") or not enc2:
            raise Fail("two of the new recovery keys did not authorize a root token")
        enc2 += "=" * (-len(enc2) % 4)
        enc2 = base64.urlsafe_b64decode(enc2) if ("-" in enc2 or "_" in enc2) else base64.b64decode(enc2)
        call(TEMP, "POST", "auth/token/revoke-self", token=bytes(a ^ b for a, b in zip(enc2, att2["otp"].encode())).decode())
        st = call(TEMP, "GET", "sys/seal-status")
        say("new recovery keys made (%d of %d) and proven (two of them authorized a root token, revoked at once)" % (st["t"], st["n"]))
        status("recovery-rekeyed", "ok", shares=st["n"], threshold=st["t"])
        counts, fails = check_keys(TEMP, token)
        say("the copy: %d keys, %d key versions round-tripped, %d failures" % (counts["transit keys"], counts["key versions round-tripped"], len(fails)))
        status("copy-verified", "ok" if not fails else "fail", counts=counts, failures=fails[:20])
        if fails:
            raise Fail("key checks failed on the copy: " + "; ".join(fails[:10]))
        snap = call(TEMP, "GET", "sys/storage/raft/snapshot", token=token, want_raw=True, timeout=300)
        say("snapshot of the copy taken (%d bytes)" % len(snap))

        # 6. Into the OpenBao cluster.
        call(LIVE, "POST", "sys/storage/raft/snapshot-force", token=live_root, raw=snap, ca=LIVE_CA, timeout=300)
        restored = True
        say("the copy is restored into the OpenBao cluster; restarting its members")
        status("restored", "ok")
        temp.terminate()
        temp.wait(30)
        temp = None
        time.sleep(3)
        restart_at = int(time.time()) - 1
        sh(RESTART_CMD)
        wait("all three members restarted, unsealed and ready", lambda: members(restart_at) == (3, 3), 600)
        wait_stable_leader()
        wait("the cluster to answer with the moved data",
             lambda: "root" in call(LIVE, "GET", "auth/token/lookup-self", token=token, ca=LIVE_CA)["data"]["policies"], 300)
        counts2, fails2 = check_keys(LIVE, token, ca=LIVE_CA)
        say("the OpenBao cluster: %d keys, %d key versions round-tripped, %d failures"
            % (counts2["transit keys"], counts2["key versions round-tripped"], len(fails2)))
        status("live-verified", "ok" if not fails2 and counts2 == counts else "fail", counts=counts2, failures=fails2[:20])
        if fails2 or counts2 != counts:
            raise Fail("key checks on the OpenBao cluster differ from the copy's")

        # 7. Root tokens the copy carried (Vault's among them).
        me = retry(lambda: call(LIVE, "GET", "auth/token/lookup-self", token=token, ca=LIVE_CA))["data"]["accessor"]
        revoked = 0
        for acc in retry(lambda: call(LIVE, "LIST", "auth/token/accessors", token=token, ca=LIVE_CA))["data"]["keys"]:
            if acc == me:
                continue
            pol = retry(lambda: call(LIVE, "POST", "auth/token/lookup-accessor", {"accessor": acc}, token=token, ca=LIVE_CA))["data"]["policies"]
            if "root" in pol:
                retry(lambda: call(LIVE, "POST", "auth/token/revoke-accessor", {"accessor": acc}, token=token, ca=LIVE_CA))
                revoked += 1
        say("revoked %d root token(s) the copy carried; only the temporary one is left" % revoked)
        status("roots-revoked", "ok", revoked=revoked)
        say("DONE. OpenBao holds the keys. Vault stays sealed. Next: the clients switch, then `move.py finish`.")
        status("done", "ok")
    except (Fail, urllib.error.URLError, subprocess.CalledProcessError, OSError, KeyError, ValueError) as e:
        msg = err_text(e) if isinstance(e, urllib.error.HTTPError) else str(e)
        say("STOPPED: " + msg[:400])
        status("stopped", "fail", reason=msg[:400], restored=restored)
        if temp:
            temp.terminate()
        if sealed_vault:
            try:
                st = unseal_with(VAULT, keys)
                say("Vault is unsealed again%s" % (" and serving; the clients never left it" if not st.get("sealed") else ": FAILED, unseal it by hand"))
                status("vault-unsealed-again", "ok" if not st.get("sealed") else "fail")
            except Exception as ue:  # noqa: BLE001
                say("could not unseal Vault again (%s): unseal it by hand" % str(ue)[:200])
                status("vault-unsealed-again", "fail")
        if restored:
            say("OpenBao keeps the copy it was given; nothing uses it yet.")
        sys.exit(1)


def finish():
    token = stash_read("t")
    new = [k for k in stash_read("rk").split("\n") if k]
    st = call(LIVE, "GET", "sys/seal-status", ca=LIVE_CA)
    if (st.get("n"), st.get("t")) != (3, 2) or len(new) != 3:
        sys.exit("OpenBao's recovery keys are not the new set yet (%s of %s): run `move.py run` first" % (st.get("t"), st.get("n")))
    while True:
        print("=" * 72)
        print(" OpenBao's NEW recovery keys (any 2 of the 3 authorize recovery).")
        print(" Store them apart from one another, offline: not on the cluster, the NAS, or anywhere an")
        print(" agent can read. They are shown here alone, and not again after you confirm.")
        print()
        for i, k in enumerate(new, 1):
            print("   %d: %s" % (i, k))
        print("=" * 72)
        print(" The recovery keys and root token from OpenBao's first setup no longer work, and Vault's")
        print(" unseal keys no longer authorize anything on OpenBao.\n")
        answer = input('Type "saved" once all three are stored: ').strip().lower()
        print("\033[2J\033[H", end="", flush=True)
        if answer == "saved":
            break
        print("Not confirmed; showing them again.\n")
    call(LIVE, "POST", "auth/token/revoke-self", token=token, ca=LIVE_CA)
    for f in ("t", "rk"):
        try:
            os.remove(os.path.join(STASH, f))
        except FileNotFoundError:
            pass
    status("finished", "ok")
    print("Done: the temporary root token is revoked, and nothing is left in this pod.")
    print("OpenBao now has no root token; the new recovery keys can make one when recovery needs it.")


def preflight():
    """No credentials, changes nothing: can the move run from here?"""
    bad = 0

    def check(name, fn):
        nonlocal bad
        try:
            note = fn() or ""
            print("  ok    %s%s" % (name, (" (%s)" % note) if note else ""))
        except Exception as e:  # noqa: BLE001
            bad += 1
            print("  FAIL  %s (%s)" % (name, (err_text(e) if isinstance(e, urllib.error.HTTPError) else str(e))[:200]))

    def tool(name, *args):
        return sh(" ".join([os.path.join(TOOLS, name)] + list(args))).strip().splitlines()[0][:60]

    check("Vault's migrate tool", lambda: tool("vault", "version"))
    check("OpenBao", lambda: tool("bao", "version"))
    check("kubectl", lambda: tool("kubectl", "version", "--client"))

    def vault_up():
        st = call(VAULT, "GET", "sys/seal-status")
        if st.get("sealed"):
            raise Fail("Vault is sealed")
        return "unsealed, %d of %d unseal keys, %s storage" % (st["t"], st["n"], st.get("storage_type"))
    check("Vault reachable and unsealed", vault_up)

    def copy_works():
        cp = subprocess.Popen(COPY_CMD, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lst = subprocess.run(["tar", "-tf", "-"], stdin=cp.stdout, capture_output=True, text=True)
        cp.stdout.close()
        if cp.wait() != 0 or lst.returncode != 0:
            raise Fail((cp.stderr.read().decode() or lst.stderr)[-200:])
        n = sum(1 for line in lst.stdout.splitlines() if not line.endswith("/"))
        if n == 0:
            raise Fail("no files")
        return "%d encrypted storage files listed, nothing decrypted" % n
    check("this pod can copy Vault's storage", copy_works)

    def three():
        n, r = members()
        if (n, r) != (3, 3):
            raise Fail("%d members, %d ready" % (n, r))
        return "3 members, 3 ready"
    check("OpenBao's members", three)

    def live_tls():
        h = call(LIVE, "GET", "sys/seal-status", ca=LIVE_CA)
        if h.get("sealed") or not h.get("initialized"):
            raise Fail("sealed or not initialized")
        return "TLS verified against %s" % LIVE_CA
    check("OpenBao's active member", live_tls)

    def unseal_host():
        out = sh(" ".join([os.path.join(TOOLS, "bao"), "status", "-format=json",
                           "-address=https://openbao-unseal-host.openbao.svc:8200",
                           "-ca-cert=/etc/unseal-host/ca.pem", "-tls-server-name=openbao-unseal-host"]) + " || true")
        d = json.loads(out or "{}")
        if d.get("sealed") is not False:
            raise Fail("not reachable, or sealed")
        return "reachable under its certificate's name, unsealed"
    check("the unseal host", unseal_host)
    check("the seal token is in this pod (not shown)", lambda: None if E("MOVE_SEAL_TOKEN") else (_ for _ in ()).throw(Fail("missing")))
    print("\npreflight: %s" % ("everything the move needs is in place" if not bad else "%d check(s) failed" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    {"run": run, "finish": finish, "preflight": preflight}.get(
        sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit("usage: move.py preflight|run|finish"))()
