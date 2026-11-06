"""The open-infra.dev website (website/) shows only what the generated coverage registry says: it reads
probe/registry/registry.json at deploy time and carries no copy of its own. This keeps the page and the
registry in step: every field the page reads exists, and the build copies the current registry."""
import json
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "probe", "registry", "registry.json")
PAGE = os.path.join(ROOT, "website", "index.html")


class Website(unittest.TestCase):
    def test_fields_the_page_reads_exist(self):
        reg = json.load(open(REGISTRY, encoding="utf-8"))
        page = open(PAGE, encoding="utf-8").read()
        for key in sorted(set(re.findall(r"sum\.(\w+)", page))):
            self.assertIn(key, reg["summary"], f"the page reads summary.{key}, which the registry does not carry")
        self.assertTrue(reg["services"], "the registry lists no services")
        for name, s in reg["services"].items():
            for key in ("service", "tier", "operations", "probes"):
                self.assertIn(key, s, f"service {name} has no {key}")
            self.assertIn(s["tier"], ("proven", "gated", "planned"), f"service {name}: unknown tier {s['tier']}")

    def test_page_carries_no_counts_of_its_own(self):
        page = open(PAGE, encoding="utf-8").read()
        reg = json.load(open(REGISTRY, encoding="utf-8"))
        for key in ("services", "operations", "covered", "cfnTypes"):
            n = str(reg["summary"][key])
            self.assertNotRegex(re.sub(r"<script>.*</script>", "", page, flags=re.S), rf">\s*{n}\s*<",
                                f"the page hard-codes the registry's {key} ({n}); read it from registry.json instead")

    def test_build_copies_the_current_registry(self):
        subprocess.run(["bash", os.path.join(ROOT, "website", "build.sh")], check=True, cwd=ROOT,
                       stdout=subprocess.DEVNULL)
        built = os.path.join(ROOT, "website", "dist", "registry.json")
        self.assertEqual(open(built, "rb").read(), open(REGISTRY, "rb").read())
        for f in ("index.html", "favicon.svg"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, "website", "dist", f)), f)


if __name__ == "__main__":
    unittest.main(verbosity=2)
