package cfn

import (
	"context"
	"strings"
	"testing"
)

const profileInstanceTmpl = `
Parameters:
  Profile: { Type: String, Default: WebProfile }
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: t3.small
      IamInstanceProfile: !Ref Profile
`

// apiProfiles are the account's instance profiles made with the IAM API: one with a role under a path, one
// with no role.
func apiProfiles() map[string]InstanceProfile {
	return map[string]InstanceProfile{
		"webprofile":   {Name: "WebProfile", Path: "/app/", Role: "web-role"},
		"emptyprofile": {Name: "EmptyProfile", Path: "/", Role: ""},
	}
}

func translateProfileInstance(t *testing.T, profile string, profiles map[string]InstanceProfile) (*Manifest, []Finding) {
	t.Helper()
	ctx := ctxWithParams(t, profileInstanceTmpl, map[string]string{"Profile": profile})
	ctx.caps.InstanceProfiles = profiles
	return translatorFor("AWS::EC2::Instance")("Web", ecsResolvedService(t, ctx, "Web"), ctx)
}

// An instance's IamInstanceProfile naming a profile the account made with the IAM API — by its name in any
// case, or by its ARN (with its path) — binds the profile's role on the VM, as EC2 launches the instance with
// the profile's role.
func TestTranslate_EC2Instance_APIInstanceProfile(t *testing.T) {
	acct := ctxWithParams(t, profileInstanceTmpl, nil).account()
	for _, v := range []string{"WebProfile", "webprofile", "arn:aws:iam::" + acct + ":instance-profile/app/WebProfile"} {
		m, fs := translateProfileInstance(t, v, apiProfiles())
		if len(fs) != 0 || m.Spec["instanceRole"] != "web-role" {
			t.Errorf("IamInstanceProfile %s: instanceRole=%v findings=%v", v, m.Spec["instanceRole"], fs)
			continue
		}
		if cav := strings.Join(m.Caveats, " | "); !strings.Contains(cav, "assumes the profile's role web-role") {
			t.Errorf("IamInstanceProfile %s: the caveat must say the role is read at create and update: %s", v, cav)
		}
	}
	// A profile with no role launches an instance with no credentials, as on AWS.
	m, fs := translateProfileInstance(t, "EmptyProfile", apiProfiles())
	if len(fs) != 0 || m.Spec["instanceRole"] != nil || !strings.Contains(strings.Join(m.Caveats, " "), "EmptyProfile has no role") {
		t.Errorf("a profile with no role: instanceRole=%v findings=%v caveats=%v", m.Spec["instanceRole"], fs, m.Caveats)
	}
}

// A profile the account does not have refuses, in EC2's words, rather than launching the instance without the
// role it names: an unknown name, an ARN with another path, an ARN of another account, something that is not
// an instance profile's ARN.
func TestTranslate_EC2Instance_UnknownInstanceProfile(t *testing.T) {
	acct := ctxWithParams(t, profileInstanceTmpl, nil).account()
	for v, want := range map[string]string{
		"NoSuchProfile": "Value (NoSuchProfile) for parameter iamInstanceProfile.name is invalid. Invalid IAM Instance Profile name",
		"arn:aws:iam::" + acct + ":instance-profile/WebProfile":        "for parameter iamInstanceProfile.arn is invalid. Invalid IAM Instance Profile ARN",
		"arn:aws:iam::111122223333:instance-profile/app/WebProfile":    "a profile of account 111122223333",
		"arn:aws:iam::" + acct + ":role/web-role":                      "Invalid IAM Instance Profile ARN",
		"arn:aws:iam::" + acct + ":instance-profile/app/NoSuchProfile": "the account has no instance profile NoSuchProfile",
	} {
		if acct == "111122223333" {
			t.Fatal("the test stack's account must not be the other account")
		}
		m, fs := translateProfileInstance(t, v, apiProfiles())
		if len(fs) != 1 || !strings.Contains(fs[0].Reason, want) {
			t.Errorf("IamInstanceProfile %s must refuse with %q: findings=%v", v, want, fs)
		}
		if m != nil && m.Spec["instanceRole"] != nil {
			t.Errorf("IamInstanceProfile %s bound a role: %v", v, m.Spec["instanceRole"])
		}
	}
	// No profile at all (an account with none) refuses the same way.
	if _, fs := translateProfileInstance(t, "WebProfile", map[string]InstanceProfile{}); len(fs) != 1 ||
		!strings.Contains(fs[0].Reason, "Invalid IAM Instance Profile name") {
		t.Errorf("an account with no profiles: %v", fs)
	}
}

// A deploy path that cannot read the account's profiles (the CLI) keeps it a caveat, as before: no role, no
// refusal.
func TestTranslate_EC2Instance_InstanceProfileWithoutStore(t *testing.T) {
	m, fs := translateProfileInstance(t, "WebProfile", nil)
	if len(fs) != 0 || m.Spec["instanceRole"] != nil || !strings.Contains(strings.Join(m.Caveats, " "), "IamInstanceProfile WebProfile names an instance profile this deploy path cannot read") {
		t.Errorf("without the profile store: instanceRole=%v findings=%v caveats=%v", m.Spec["instanceRole"], fs, m.Caveats)
	}
}

// An in-stack profile still resolves to its in-stack role, never to an account profile of its name.
func TestTranslate_EC2Instance_InStackProfileWithAccountProfiles(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	ctx.caps.InstanceProfiles = map[string]InstanceProfile{}
	m, fs := translateEC2Instance("AppInstance", resolvedProps(t, ctx, "AppInstance"), ctx)
	if len(fs) != 0 || m.Spec["instanceRole"] != "approle" {
		t.Fatalf("the in-stack profile's role: instanceRole=%v findings=%s", m.Spec["instanceRole"], findingsText(fs))
	}
}

// The role reaches the deployed VM, and a profile the account does not have refuses the deploy.
func TestDeploy_APIInstanceProfileRole(t *testing.T) {
	f := &fakeApplier{}
	opts := deployOpts()
	opts.Caps.InstanceProfiles = apiProfiles()
	if _, err := Deploy(context.Background(), []byte(profileInstanceTmpl), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got := f.liveSpecs["VirtualMachine/s-web"]["instanceRole"]; got != "web-role" {
		t.Fatalf("the deployed VM's instanceRole = %v", got)
	}
	opts.Params = map[string]string{"Profile": "NoSuchProfile"}
	f = &fakeApplier{}
	if _, err := Deploy(context.Background(), []byte(profileInstanceTmpl), opts, f); err == nil || !strings.Contains(err.Error(), "Invalid IAM Instance Profile name") {
		t.Fatalf("a profile the account does not have must refuse the deploy: %v", err)
	}
	if len(f.applied) != 0 {
		t.Fatalf("a refused deploy applies nothing: %v", f.applied)
	}
}
