package render

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The app-of-apps root (platform/root-app.yaml) syncs platform/ with a directory
// generator: include '{<areas>}/*.yaml', exclude __EXCLUDE__ (from install.sh). Argo's
// glob does NOT treat '/' as a separator, so '*' spans path segments — every.yaml under
// an included area (top-level OR nested) is picked up. Anything picked up that is not a
// manifest the API server serves makes Argo abort the WHOLE platform sync, wedging every
// component until it is fixed.
//
// install.sh's base EXCLUDES is a HAND-MAINTAINED mirror of the files that must NOT be
// applied by the root app: the console/query manifests/ (deployed by their own child
// app), security/apiserver/* (kube-apiserver config read off disk), and the CI-only
// abstraction/policy-boundary.yaml. Drop a new non-resource file under an area without
// adding it to that list and the next sync wedges — silently, because nothing here
// exercises it.
//
// This is the guard, in the boundary-checker style: every.yaml under an included area is
// EITHER excluded by install.sh, OR a top-level manifest the root app can legitimately
// apply. The areas come from root-app.yaml and the globs from install.sh, so the test
// tracks both sources of truth instead of becoming a third copy to drift.
func TestArgoExcludeListNoDrift(t *testing.T) {
	areas := includeAreas(t)
	globs := baseExcludes(t)

	for _, area := range areas {
		dir := filepath.Join("../../platform", area)
		if _, err := os.Stat(dir); err != nil {
			continue // an included area with no directory yet is fine
		}
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
				return err
			}
			rel, relErr := filepath.Rel("../../platform", p)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)

			if excludedByArgo(rel, globs) {
				return nil // deployed by a child app / read off disk — not root-app state
			}
			// Not excluded ⇒ the root app WILL apply this file directly.
			if segs := strings.Split(rel, "/"); len(segs) != 2 {
				t.Errorf("%s is nested and NOT excluded: the root-app include picks it up "+
					"('*' spans '/') and applies it as raw state — double-owning it, or, if it "+
					"isn't a served kind, wedging the whole platform sync. Add a matching glob to "+
					"install.sh EXCLUDES (e.g. **/manifests/**) or move it out of an included area.", rel)
				return nil
			}
			if firstKind(t, p) == "" {
				t.Errorf("%s has no top-level 'kind:' — the root app would try to apply a "+
					"non-manifest and Argo aborts the ENTIRE platform sync. Add it to install.sh "+
					"EXCLUDES (this is exactly why abstraction/policy-boundary.yaml is excluded).", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}

// includeAreas parses the '{a,b,c}/*.yaml' include glob out of platform/root-app.yaml —
// the authoritative list of directories the root app scans.
func includeAreas(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../platform/root-app.yaml")
	if err != nil {
		t.Fatalf("read root-app.yaml: %v", err)
	}
	m := regexp.MustCompile(`include:\s*'?\{([^}]*)\}`).FindSubmatch(b)
	if m == nil {
		t.Fatal("could not find the include: '{...}' glob in root-app.yaml — did its shape change?")
	}
	var areas []string
	for _, a := range strings.Split(string(m[1]), ",") {
		if a = strings.TrimSpace(a); a != "" {
			areas = append(areas, a)
		}
	}
	if len(areas) == 0 {
		t.Fatal("root-app.yaml include glob parsed to zero areas")
	}
	return areas
}

// baseExcludes parses the first `EXCLUDES="..."` assignment in install.sh — the always-on
// wedge guard. Component-toggle excludes append later (`${EXCLUDES},...`) and gate valid
// manifests, so they are not part of this invariant.
func baseExcludes(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	m := regexp.MustCompile(`(?m)^EXCLUDES="([^"]*)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("could not find the base EXCLUDES=\"...\" line in install.sh")
	}
	var globs []string
	for _, g := range strings.Split(string(m[1]), ",") {
		if g = strings.TrimSpace(g); g != "" {
			globs = append(globs, g)
		}
	}
	if len(globs) == 0 {
		t.Fatal("install.sh base EXCLUDES parsed to zero globs")
	}
	return globs
}

// excludedByArgo mirrors how Argo matches the exclude globs here: '*' (and '**') span '/'.
// A glob is turned into an anchored regexp with every '*' as '.*', so 'security/apiserver/**'
// matches 'security/apiserver/audit-policy.yaml' and '**/manifests/**' matches any nested
// manifests/ file — exactly the semantics root-app.yaml documents.
func excludedByArgo(rel string, globs []string) bool {
	for _, g := range globs {
		q := regexp.QuoteMeta(g)          // escapes '.', '-', … and turns '*' into '\*'
		q = strings.ReplaceAll(q, `\*`, `.*`)
		if regexp.MustCompile("^" + q + "$").MatchString(rel) {
			return true
		}
	}
	return false
}

// firstKind returns the first top-level (column-0) 'kind:' value in a manifest, or "" if
// the file has none — the signal that it is not a Kubernetes manifest at all.
func firstKind(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "kind:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "kind:"))
		}
	}
	return ""
}
