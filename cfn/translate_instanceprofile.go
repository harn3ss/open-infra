package cfn

import "strings"

// ec2InstanceProfile maps an AWS::EC2::Instance IamInstanceProfile onto the VM's spec.instanceRole: the role
// the instance's credentials (EC2 instance metadata) are for.
//
//   - A Ref or Fn::GetAtt to an in-stack AWS::IAM::InstanceProfile follows the profile to its first Roles
//     entry, an in-stack AWS::IAM::Role (resolveInstanceRole).
//   - Any other value names an instance profile of the stack's account by its name or its ARN
//     (arn:aws:iam::<account>:instance-profile<path><name>), one made with the IAM API: the deploying
//     environment holds them (Capabilities.InstanceProfiles, the aws-shim's CreateInstanceProfile /
//     AddRoleToInstanceProfile), and the profile's role binds on the VM. A profile the account does not
//     have refuses, as EC2 refuses to launch an instance with one. Without the profile store (the CLI) it
//     stays a caveat and the instance gets no role.
func ec2InstanceProfile(id string, props map[string]any, ctx *stackCtx, spec map[string]any, f []Finding, cav []string) ([]Finding, []string) {
	if _, present := props["IamInstanceProfile"]; !present {
		return f, cav
	}
	if role, ok := resolveInstanceRole(id, ctx); ok {
		spec["instanceRole"] = role
		return f, cav
	}
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if t, isRef := getAttTarget(raw["IamInstanceProfile"]); isRef {
				if _, in := ctx.template.Resources[t]; in {
					return f, append(cav, "IamInstanceProfile could not be resolved to an in-stack AWS::IAM::Role — set spec.instanceRole to the kind: Role the VM should assume (it must trust the vm principal)")
				}
			}
		}
	}
	v, ok := concrete(props["IamInstanceProfile"])
	if !ok || v == "" {
		return append(f, Finding{"Resource " + id, "IamInstanceProfile could not be resolved to an instance profile's name or ARN"}), cav
	}
	name, path, isARN := v, "", strings.HasPrefix(v, "arn:")
	if isARN {
		parts := strings.SplitN(v, ":", 6)
		if len(parts) != 6 || parts[2] != "iam" || !strings.HasPrefix(parts[5], "instance-profile/") {
			return append(f, Finding{"Resource " + id, "IamInstanceProfile: Value (" + v + ") for parameter iamInstanceProfile.arn is invalid. Invalid IAM Instance Profile ARN"}), cav
		}
		if ctx != nil && parts[4] != ctx.account() {
			return append(f, Finding{"Resource " + id, "IamInstanceProfile: Value (" + v + ") for parameter iamInstanceProfile.arn is invalid. Invalid IAM Instance Profile ARN — it is a profile of account " + parts[4] + ", and an instance's profile is one of its own account (" + ctx.account() + ")"}), cav
		}
		res := strings.TrimPrefix(parts[5], "instance-profile")
		i := strings.LastIndex(res, "/")
		path, name = res[:i+1], res[i+1:]
	}
	if ctx == nil || ctx.caps.InstanceProfiles == nil {
		return f, append(cav, "IamInstanceProfile "+v+" names an instance profile this deploy path cannot read — the instance gets no role. Deploy through the aws-shim's CloudFormation front door, which binds the role of a profile made with iam create-instance-profile and iam add-role-to-instance-profile")
	}
	p, ok := ctx.caps.InstanceProfiles[strings.ToLower(name)]
	if ok && isARN && p.Path != path {
		ok = false // the ARN names the profile's path too: another path is another profile
	}
	if !ok {
		param, what := "name", "name"
		if isARN {
			param, what = "arn", "ARN"
		}
		return append(f, Finding{"Resource " + id, "IamInstanceProfile: Value (" + v + ") for parameter iamInstanceProfile." + param +
			" is invalid. Invalid IAM Instance Profile " + what + " — the account has no instance profile " + name +
			"; create it first (aws iam create-instance-profile --instance-profile-name " + name +
			") or declare an AWS::IAM::InstanceProfile in the stack"}), cav
	}
	if p.Role == "" {
		return f, append(cav, "IamInstanceProfile "+p.Name+" has no role, so the instance gets no credentials, as on AWS. The profile is read when the stack is created or updated: a role added to it later reaches the instance at the stack's next update")
	}
	spec["instanceRole"] = p.Role
	return f, append(cav, "IamInstanceProfile "+p.Name+": the instance assumes the profile's role "+p.Role+". The profile is read when the stack is created or updated: a change to its role reaches the instance at the stack's next update (on AWS a running instance follows its profile)")
}
