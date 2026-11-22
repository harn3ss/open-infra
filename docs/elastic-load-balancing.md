# Elastic Load Balancing: network load balancers

open-infra serves Elastic Load Balancing's **Network Load Balancers** in front of EC2 instances, through the
Elastic Load Balancing API (`aws elbv2 …`, API version 2015-12-01). A network load balancer listens on TCP,
UDP or TCP_UDP ports and forwards each connection or datagram to the instances registered in its target
group. As on AWS with instance targets, it passes the **client's own address** to the instance, so the
instance's security groups decide which clients reach it.

A load balancer here is **internet-facing**. On this platform, "the internet" is the network the
installation's load-balancer addresses are reachable from (for most installations, the site's LAN), not the
public internet.

## Before you start

- A load balancer is placed in a **public subnet** of the account's default VPC: a subnet whose route table
  sends `0.0.0.0/0` to an internet gateway. `aws ec2 describe-route-tables` shows which subnets those are.
  If the default VPC has its internet gateway, its default subnet is public. If it has none, ask the
  platform's operator for a public subnet. It attaches an internet gateway for that subnet alone, and the
  default subnet keeps no route to it.
- The targets are instances in the same VPC.

## Example: one UDP port to one instance

```sh
VPC=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
PUBLIC=$(aws ec2 describe-route-tables --filters Name=vpc-id,Values=$VPC \
  --query "RouteTables[?Routes[?DestinationCidrBlock=='0.0.0.0/0']].Associations[].SubnetId | [0]" --output text)

TG=$(aws elbv2 create-target-group --name game --protocol UDP --port 27015 --vpc-id "$VPC" \
  --target-type instance --query 'TargetGroups[0].TargetGroupArn' --output text)
aws elbv2 register-targets --target-group-arn "$TG" --targets Id=i-0123456789abcdef0

LB=$(aws elbv2 create-load-balancer --name game-nlb --type network --scheme internet-facing \
  --subnets "$PUBLIC" --query 'LoadBalancers[0].LoadBalancerArn' --output text)
aws elbv2 create-listener --load-balancer-arn "$LB" --protocol UDP --port 27015 \
  --default-actions Type=forward,TargetGroupArn="$TG"

aws elbv2 wait load-balancer-available --load-balancer-arns "$LB"
aws elbv2 describe-load-balancers --load-balancer-arns "$LB" \
  --query 'LoadBalancers[0].AvailabilityZones[0].LoadBalancerAddresses[0].IpAddress' --output text
```

Clients connect to that address on the listener's port. Then let the clients in with the instance's
security group. With client address preservation, the rule names the clients, not the load balancer:

```sh
aws ec2 authorize-security-group-ingress --group-id sg-0123456789abcdef0 \
  --ip-permissions 'IpProtocol=udp,FromPort=27015,ToPort=27015,IpRanges=[{CidrIp=192.0.2.22/32}]'
```

A client the group does not admit gets nothing back, as on AWS.

## An instance with no route out

An instance in a subnet with no route to the internet (a default VPC without its internet gateway) still
answers the clients a load balancer brings it: replies to their traffic go back through the load balancer.
It cannot start a connection of its own to anywhere outside the platform. That's how a private-subnet
instance behind an AWS network load balancer works.

## Target health

`aws elbv2 describe-target-health` reports each registered target:

| State | Reason | When |
|---|---|---|
| `healthy` | — | its instance is running and receiving traffic |
| `initial` | `Elb.InitialHealthChecking` | its instance is starting |
| `unused` | `Target.InvalidState` | its instance is stopped (or terminated) |
| `unused` | `Target.NotInUse` | the target group is not used by a listener |
| `unused` | `Target.NotRegistered` | the instance asked about is not registered |

A terminated instance leaves its target groups, as AWS deregisters it.

## Permissions

Each action is `elasticloadbalancing:<Action>`, decided on the resource's ARN as AWS writes it:

- `arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/net/<name>/<id>`
- `arn:aws:elasticloadbalancing:<region>:<account>:targetgroup/<name>/<id>`
- `arn:aws:elasticloadbalancing:<region>:<account>:listener/net/<lb name>/<lb id>/<id>`

Wildcards work in them, as on AWS (`loadbalancer/net/game-*/*`). `CreateListener` is decided on the load
balancer's ARN, `RegisterTargets` and `DeregisterTargets` on the target group's. The `Describe*` actions are
decided on `"*"`, as AWS has no resource-level permission for them. Tags given at creation need
`elasticloadbalancing:AddTags` as well. A principal whose policy does not allow an action is refused with
`AccessDenied`. Each account's load balancers are its own.

## Served operations

`CreateLoadBalancer`, `DescribeLoadBalancers`, `DeleteLoadBalancer`, `DescribeLoadBalancerAttributes`,
`CreateTargetGroup`, `DescribeTargetGroups`, `DeleteTargetGroup`, `DescribeTargetGroupAttributes`,
`RegisterTargets`, `DeregisterTargets`, `DescribeTargetHealth`, `CreateListener`, `DescribeListeners`,
`DeleteListener`, `AddTags`, `RemoveTags`, `DescribeTags`. `CreateLoadBalancer`, `CreateTargetGroup` and
`CreateListener` are idempotent, as on AWS: the same name and settings return the same resource.

## Differences from AWS

- **Network load balancers only.** An Application or Gateway Load Balancer (`--type application`, the API's
  default, or `gateway`) is refused: pass `--type network`.
- **Internet-facing only**, in a public subnet. An internal load balancer is refused. So is an
  internet-facing one in a subnet with no route to an internet gateway: AWS accepts that one, but it would
  not work there either.
- **No load balancer security groups.** `--security-groups` is refused: the target's security groups decide,
  with the client's address.
- **TCP, UDP and TCP_UDP**; TLS listeners and target groups are refused, as are IP, Lambda and ALB targets
  and subnet mappings with an Elastic IP or a chosen private address.
- **Health checks are not sent.** A target group's health check settings are kept and reported, and a target
  is healthy while its instance runs.
- **The DNS name** (`<name>-<id>.elb.<region>.amazonaws.com`) is in AWS's form, but clients outside the
  platform cannot resolve it: connect to the address `DescribeLoadBalancers` reports in
  `AvailabilityZones[].LoadBalancerAddresses[].IpAddress`.
- **One Availability Zone**, so one subnet per load balancer.
- **Not created by CloudFormation yet.** `AWS::ElasticLoadBalancingV2::*` resources are refused in a
  template, so create load balancers with the API.
- `Modify*`, `SetSubnets`, `SetSecurityGroups`, listener rules and certificates are not served.
