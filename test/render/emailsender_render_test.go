package render

import (
	"strings"
	"testing"
)

const emailsenderCompositionPath = "../../platform/abstraction/emailsender-composition.yaml"

func emailsenderCtx(spec map[string]any) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"labels": map[string]any{
					"crossplane.io/claim-name":      "notify",
					"crossplane.io/claim-namespace": "shop",
				},
			},
		}}},
	}
}

// The connection secret points apps at the shared relay with their From identity.
func TestEmailSender_ConnectionSecret(t *testing.T) {
	tmpl := extractInlineTemplate(t, emailsenderCompositionPath)
	out := render(t, tmpl, emailsenderCtx(map[string]any{
		"fromAddress": "noreply@example.com", "fromName": "Acme Notifications",
	}))

	if !strings.Contains(out, "name: notify-smtp") {
		t.Errorf("should emit a <name>-smtp secret; got:\n%s", grepCtx(out, "smtp"))
	}
	if !strings.Contains(out, "SMTP_HOST: smtp-relay.mail.svc.cluster.local") || !strings.Contains(out, `SMTP_PORT: "587"`) {
		t.Errorf("secret should point at the in-cluster relay; got:\n%s", grepCtx(out, "SMTP_"))
	}
	if !strings.Contains(out, `SMTP_FROM: "noreply@example.com"`) || !strings.Contains(out, `SMTP_FROM_NAME: "Acme Notifications"`) {
		t.Errorf("secret should carry the From identity; got:\n%s", grepCtx(out, "SMTP_FROM"))
	}
	if !strings.Contains(out, "connectionSecret: notify-smtp") || !strings.Contains(out, "ready: true") {
		t.Errorf("status should report the connection secret + ready; got:\n%s", grepCtx(out, "connectionSecret"))
	}
}
