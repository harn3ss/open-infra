package render

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The function resolver answers AWS's names exactly as the VM guests' resolver does (#335): the same rules
// send the same amazonaws.com names to the platform, and every other amazonaws.com name only the function
// resolver sinkholes. One list, kept in two Corefiles, held equal here.
func corefileRewrites(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ln := range strings.Split(string(raw), "\n") {
		if l := strings.TrimSpace(ln); strings.HasPrefix(l, "rewrite stop name regex ") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s has no rewrite rules", path)
	}
	return out
}

func TestFunctionDNS_SameAWSNamesAsTheGuestResolver(t *testing.T) {
	guest := corefileRewrites(t, "../../platform/aws-shim/guest-aws-endpoints.yaml")
	fn := corefileRewrites(t, "../../platform/aws-shim/function-aws-endpoints.yaml")
	if !reflect.DeepEqual(guest, fn) {
		t.Errorf("the function resolver's rules differ from the guest resolver's:\n guest: %q\n function: %q", guest, fn)
	}
}

// The function resolver sinkholes the rest of amazonaws.com, and nothing else.
func TestFunctionDNS_SinkholesOnlyAmazonaws(t *testing.T) {
	raw, err := os.ReadFile("../../platform/aws-shim/function-aws-endpoints.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"template ANY ANY amazonaws.com {", "rcode NXDOMAIN", "log amazonaws.com {", "class denial",
		"forward . 127.0.0.1:1053", "bind 127.0.0.1", "clusterIP: 10.43.0.54"} {
		if !strings.Contains(s, want) {
			t.Errorf("function-aws-endpoints.yaml lacks %q", want)
		}
	}
	if n := len(regexp.MustCompile(`(?m)^\s+template `).FindAllString(s, -1)); n != 1 {
		t.Errorf("want exactly one template (the amazonaws.com sinkhole), got %d", n)
	}
}
