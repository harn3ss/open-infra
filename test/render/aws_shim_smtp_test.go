package render

import "testing"

// The aws-shim serves the SES SMTP interface on SES's ports: the Service's 587 (STARTTLS) and 465 (TLS
// Wrapper) reach the shim's unprivileged listeners, which the Deployment configures.
func TestAWSShim_ServesTheSESSMTPInterface(t *testing.T) {
	raw := mustRead(t, "../../platform/aws-shim/aws-shim.yaml")
	docs, err := parseYAMLDocs(raw)
	if err != nil {
		t.Fatal(err)
	}
	var svcPorts, ctrPorts []any
	env := map[string]string{}
	for _, d := range docs {
		switch {
		case d["kind"] == "Service" && mstr(d, "metadata", "name") == "aws-shim":
			svcPorts, _ = mget(d, "spec", "ports").([]any)
		case d["kind"] == "Deployment" && mstr(d, "metadata", "name") == "aws-shim":
			cs, _ := mget(d, "spec", "template", "spec", "containers").([]any)
			for _, c := range cs {
				if mstr(c, "name") != "aws-shim" {
					continue
				}
				ctrPorts, _ = mget(c, "ports").([]any)
				es, _ := mget(c, "env").([]any)
				for _, e := range es {
					env[mstr(e, "name")] = mstr(e, "value")
				}
			}
		}
	}
	want := map[string][2]string{"smtp": {"587", "2587"}, "smtps": {"465", "2465"}}
	for name, pp := range want {
		found := false
		for _, p := range svcPorts {
			if mstr(p, "name") == name && mstr(p, "port") == pp[0] && mstr(p, "targetPort") == pp[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("the aws-shim Service must map %s %s -> %s, got %v", name, pp[0], pp[1], svcPorts)
		}
		found = false
		for _, p := range ctrPorts {
			if mstr(p, "name") == name && mstr(p, "containerPort") == pp[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("the aws-shim container must declare %s on %s, got %v", name, pp[1], ctrPorts)
		}
	}
	if env["SES_SMTP_LISTEN_ADDR"] != ":2587" || env["SES_SMTPS_LISTEN_ADDR"] != ":2465" {
		t.Errorf("the shim must listen for SMTP on :2587 and SMTPS on :2465, got %q / %q", env["SES_SMTP_LISTEN_ADDR"], env["SES_SMTPS_LISTEN_ADDR"])
	}
	if env["INTERNAL_TLS_CERT_FILE"] == "" || env["INTERNAL_TLS_KEY_FILE"] == "" {
		t.Error("the SMTP interface's STARTTLS needs the in-cluster certificate (INTERNAL_TLS_CERT_FILE/KEY)")
	}
}
