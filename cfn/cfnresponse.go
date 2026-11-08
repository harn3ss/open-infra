package cfn

import _ "embed"

// The cfn-response modules open-infra puts beside inline (Code.ZipFile) code that loads them, where AWS
// provides its own: cfn-response for Node.js, cfnresponse for Python. Each PUTs a custom resource's
// response to the event's ResponseURL, which the aws-shim serves (#404).
var (
	//go:embed cfnresponse/cfn-response.js
	cfnResponseNode string
	//go:embed cfnresponse/cfnresponse.py
	cfnResponsePython string
)
