module github.com/harn3ss/open-infra/scripts/iam-migrate

go 1.26.4

require (
	github.com/harn3ss/open-infra/cfn v0.0.0-00010101000000-000000000000
	github.com/harn3ss/open-infra/policyengine v0.0.0-00010101000000-000000000000
)

require (
	github.com/cedar-policy/cedar-go v1.8.0 // indirect
	golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/harn3ss/open-infra/cfn => ../../cfn
	github.com/harn3ss/open-infra/policyengine => ../../policyengine
)
