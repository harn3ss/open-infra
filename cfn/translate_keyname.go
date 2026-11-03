package cfn

import "strings"

// ec2KeyName maps an AWS::EC2::Instance KeyName (#347 item 24): the named key pair's public key, from the
// key pairs the deploying environment holds (Capabilities.KeyPairs: the aws-shim's ImportKeyPair /
// CreateKeyPair), goes into the VM's spec.sshKey, which cloud-init authorizes for the image's login user
// on first boot, as EC2 does. A name the environment does not hold refuses, as AWS's
// InvalidKeyPair.NotFound fails the instance. Without the key-pair store (the CLI) it stays a caveat.
func ec2KeyName(id string, props map[string]any, ctx *stackCtx, spec map[string]any, f []Finding, cav []string) ([]Finding, []string) {
	name, ok := concrete(props["KeyName"])
	if !ok || name == "" {
		if _, present := props["KeyName"]; present {
			f = append(f, Finding{"Resource " + id, "KeyName could not be resolved to a key pair's name"})
		}
		return f, cav
	}
	if ctx == nil || ctx.caps.KeyPairs == nil {
		return f, append(cav, "KeyName "+name+" names an EC2 key pair this deploy path cannot read — no key is injected; a login password is generated (in the <name>-vm secret). Deploy through the aws-shim's CloudFormation front door, which carries an imported key pair (ec2 import-key-pair) into spec.sshKey")
	}
	pub, ok := ctx.caps.KeyPairs[name]
	if !ok || pub == "" {
		f = append(f, Finding{"Resource " + id, "KeyName " + name + ": the key pair does not exist (InvalidKeyPair.NotFound) — import it first (aws ec2 import-key-pair --key-name " + name + " --public-key-material fileb://<key>.pub)"})
		return f, cav
	}
	spec["sshKey"] = strings.TrimSpace(pub)
	if os, _ := spec["os"].(string); strings.HasPrefix(os, "windows-") {
		cav = append(cav, "KeyName on a Windows instance: the key is not used to encrypt the Administrator password (GetPasswordData is not served); the password is in the <name>-vm secret")
	}
	return f, cav
}
