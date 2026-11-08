# Lambda functions in a VPC

A Lambda function can be put in a VPC, as on AWS, to control what it reaches and to record what it tries.
AWS has no single "isolated" switch, and neither does open-infra. The isolation is built from the same
four AWS features:

| What you want | The AWS feature | Here |
|---|---|---|
| Outbound traffic denied, except an allow-list | Lambda `VpcConfig` + the security groups' outbound rules | the function's security groups, enforced by the network |
| DNS that cannot leak a name | Route 53 Resolver DNS Firewall, associated with the VPC | the VPC resolver applies the VPC's rule groups |
| Every DNS query recorded | Route 53 Resolver query logging | one record per query, in your log group |
| Every refused connection recorded | VPC Flow Logs, `TrafficType REJECT` | one record per refused flow, in your log group |

## Putting a function in a VPC

`aws lambda create-function … --vpc-config SubnetIds=<subnet>,<subnet>,SecurityGroupIds=<group>`, or
`update-function-configuration --vpc-config …`. CloudFormation: `AWS::Lambda::Function` `VpcConfig`. As on
Lambda:

- **Subnets and groups together.**
  - Give 1–16 subnets and 1–5 security groups, all of one VPC of your account.
  - A subnet or group that does not exist is refused with EC2's `InvalidSubnetID.NotFound` /
    `InvalidGroup.NotFound`.
  - An empty `VpcConfig` takes the function out of its VPC.
- **The execution role** must allow `ec2:CreateNetworkInterface`, `ec2:DescribeNetworkInterfaces` and
  `ec2:DeleteNetworkInterface` (the `AWSLambdaVPCAccessExecutionRole` permissions). If it does not, the call
  is refused: "The provided execution role does not have permissions to call CreateNetworkInterface on EC2".
- **The configuration answers it:** `get-function-configuration` returns `VpcConfig` with its `VpcId`.
- **Network interfaces:** `aws ec2 describe-network-interfaces --filters Name=vpc-id,Values=<vpc>` lists the
  function's interfaces, one per subnet, `InterfaceType lambda`, described "AWS Lambda VPC ENI-<function>".
  A flow-log record names the interface.

A security group a function uses belongs to the VPC: CloudFormation's `AWS::EC2::SecurityGroup` `VpcId` (a
`!Ref` to the stack's VPC).

## What a function in a VPC can reach

- **Outbound: exactly what its security groups allow.**
  - A group with outbound rules allows those destinations and ports, and refuses everything else.
  - A group with no outbound rules allows all outbound traffic, as AWS's default rule does.
  - A rule names the port the destination listens on.
- **Always reachable, whatever the security groups say, as on AWS:**
  - **the VPC's resolver**, for DNS;
  - **the Lambda service**: the function's own deployment package and its execution role's credentials,
    and nothing else.
- **The function's own calls to AWS APIs** go to the platform's AWS endpoint, and its security groups
  govern them. To call AWS from an isolated function, allow that endpoint in a security group, as on AWS you
  would add a VPC endpoint or a NAT gateway.
- **DNS: only the VPC's resolver.**
  - A DNS packet (UDP or TCP port 53) to any other address is dropped by the network, before any security
    group is consulted.
  - The resolver applies the VPC's DNS Firewall:
    - rule groups in association-priority order, then rules in priority order;
    - `ALLOW` resolves the name; `BLOCK` answers `NXDOMAIN`, `NODATA` or the `OVERRIDE` record, and the name
      is **never looked up**; `ALERT` records and goes on;
    - `INSPECT_REDIRECTION_DOMAIN` (the default) checks every name in a CNAME chain too.
  - With no rule group associated, every name resolves.
- **Inbound: only invocations**, as for any Lambda function (Invoke and event sources).

### A walled garden

The AWS pattern for "resolve cluster names only":

```sh
aws route53resolver create-firewall-domain-list --creator-request-id a --name cluster-names
aws route53resolver update-firewall-domains --firewall-domain-list-id <allow> --operation ADD --domains '*.cluster.local'
aws route53resolver create-firewall-domain-list --creator-request-id b --name everything
aws route53resolver update-firewall-domains --firewall-domain-list-id <all> --operation ADD --domains '*'
aws route53resolver create-firewall-rule-group --creator-request-id c --name walled-garden
aws route53resolver create-firewall-rule --creator-request-id d --firewall-rule-group-id <group> \
  --firewall-domain-list-id <allow> --priority 100 --action ALLOW --name allow-cluster
aws route53resolver create-firewall-rule --creator-request-id e --firewall-rule-group-id <group> \
  --firewall-domain-list-id <all> --priority 200 --action BLOCK --block-response NXDOMAIN --name block-the-rest
aws route53resolver associate-firewall-rule-group --creator-request-id f --firewall-rule-group-id <group> \
  --vpc-id <vpc> --priority 101 --name walled-garden
```

Domain names match as DNS Firewall matches them, ignoring case and a trailing dot:
- `example.com` matches only itself;
- a leading `*` matches any name that ends with the rest, so `*.example.com` matches the subdomains but not
  `example.com`;
- `*` alone matches everything.

## What is recorded

- **DNS queries:**
  - `create-resolver-query-log-config --destination-arn arn:aws:logs:<region>:<account>:log-group:<group>`,
    then `associate-resolver-query-log-config --resource-id <vpc>`.
  - Each query from a function in the VPC is one JSON record in AWS's format: `query_name`, `query_type`,
    `rcode`, the answers, `srcaddr`, and `firewall_rule_action` / `firewall_rule_group_id` /
    `firewall_domain_list_id` when an `ALERT` or `BLOCK` rule matched.
  - A `BLOCK` record is the resolver's own statement that it answered without resolving the name.
- **Refused connections:**
  - `aws ec2 create-flow-logs --resource-type VPC|Subnet|NetworkInterface --resource-ids … --traffic-type
    REJECT --log-destination-type cloud-watch-logs --log-group-name <group> --deliver-logs-permission-arn
    <role>`. The role trusts `vpc-flow-logs.amazonaws.com` and may write to the group; if it cannot,
    `describe-flow-logs` shows `DeliverLogsStatus FAILED`.
  - Each record is in the default format (version 2): interface, source and destination address and port,
    protocol, packets, start, end, `REJECT`.
  - One log stream per network interface, published per aggregation window (`--max-aggregation-interval`
    60 or 600 seconds).
- **Who may read them:** both are ordinary CloudWatch Logs groups. Reading them takes `logs:*` permissions
  on those groups alone, not access to the function's own logs (`/aws/lambda/<function>`), which can carry
  its environment.

## Differences from AWS

- **Addresses.** A function's network interfaces take their addresses from the platform's Lambda VPC
  network, not from its subnets' CIDRs. A security group rule that names an in-VPC CIDR does not match a
  function.
- **Routes and network ACLs are not applied to a function's traffic.**
  - Its security groups alone decide what it reaches, the internet included.
  - On AWS a private subnet without a NAT gateway also has no internet; here, give the function a security
    group with outbound rules.
- **Flow logs.**
  - Only `TrafficType REJECT` is served; `ACCEPT` and `ALL` are refused.
  - `bytes` is not measured and is 0. `packets` counts the refused packets, a retransmitted connection
    attempt once each time.
  - A DNS packet to a resolver other than the VPC's is dropped without a record.
  - A connection refused before it reaches a function is not recorded (a Lambda function accepts none).
- **Destinations.**
  - Query logs and flow logs are delivered to CloudWatch Logs only. Amazon S3 and Kinesis Data Firehose
    destinations are refused.
- **Not served:**
  - DNS Firewall Advanced and AWS-managed domain lists;
  - `Ipv6AllowedForDualStack`;
  - the IAM condition keys `lambda:VpcIds`, `lambda:SubnetIds` and `lambda:SecurityGroupIds`.
- **The management account:** a function it made without a VPC cannot be moved into one; create it again
  with its `VpcConfig`. A member account's functions can.

## Operator notes

This section is for the platform's operator.

- **The Lambda VPC subnet.**
  - `platform/networking/kube-ovn/lambda-vpc-subnet.yaml` defines the kube-ovn subnet `openinfra-lambda-vpc`
    (10.17.0.0/16, in the default kube-ovn VPC, not private).
  - VPC functions' pods run on it. Its ACL drops every DNS packet that is not to the VPC resolver; that ACL is
    evaluated before any NetworkPolicy and wins over a NetworkPolicy's allow.
  - The CIDR must be free on your network and in the cluster; change it there if not.
- **The VPC resolver** is the `vpc-resolver` Service, `10.43.0.2` (`platform/aws-shim/lambda-vpc.yaml`),
  served by the aws-shim on `:5353`. On a cluster with another Service CIDR, change its address there, in the
  `openinfra-lambda-vpc` EnvironmentConfig and in the subnet's ACL (a render test checks all three agree).
- **The Lambda service port** is the aws-shim's `:4568`. It serves `/v1/function-code` and unsigned
  `AssumeRoleWithWebIdentity`, and answers everything else 404.
- **Security groups in a VPC** (`spec.vpc`) are annotated so OVN logs every packet they drop (`acl_log`
  lines on each node's `ovs-ovn` pod). The aws-shim reads them from Loki and delivers flow-log records.
  Allowed traffic is not logged: OVN would log every packet of it, unmetered.
- **Other NetworkPolicies selecting a VPC function's pods** weaken the posture: a policy that allows more
  widens what the function reaches, and an unlogged policy's drop can win over a logged one, so a refusal
  goes unrecorded. Let only the function's security groups select its pods. (DNS stays contained either
  way: the subnet ACL wins over any policy.)
- **Proof:** `probe/aws-shim-lambda-vpc.sh` runs the whole posture through the AWS CLI on a managed runtime
  and on an unsupported runtime image. On a pass it writes an attestation.
