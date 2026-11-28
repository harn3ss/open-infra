# NAT gateways: operator guide

*This is an operator guide: it speaks of kube-ovn subnets, nodes and Kubernetes resources, which customers
never see. What a customer gets is in [the aws-shim's EC2 front door](aws-shim.md#ec2-the-platforms-vms-volumes-groups-vpcs-and-subnets-key-pairs-ec2-query-protocol-probe-proven), under "A NAT gateway and a private subnet".*

A member account's default VPC can have a NAT gateway in its public subnet and a private subnet whose route
table sends a few internet destinations, and only them, to that gateway. Use it when an account's instances
must reach a handful of addresses on the internet and nothing else, in a VPC that otherwise has no route out.

## How it is built

- **The private subnet** is the kube-ovn Subnet `default-vpc-<account>-private` on `ovn-cluster`, rendered by
  the Account composition from `spec.defaultVpc.privateSubnet`. It is a /24 of `172.31.0.0/16`, labelled
  `openinfra.dev/internet-gateway: "false"` so the VPC resolver treats its senders as having no route out.
  No namespace is bound to it: a workload joins it by naming it.
- **The NAT gateway** is one node, `networking.natGateway.node` in `config.yaml`. The private subnet is a
  *centralized* subnet on that node (`gatewayType: centralized`, `gatewayNode`) with `natOutgoing: true`.
  Its traffic to the internet goes through that node and leaves with the node's address, which EC2 reports
  as the gateway's Elastic IP.
- **The routes** are enforced by the subnet's network ACL. Priority 3000 drops every destination but the
  platform's networks, the account's own subnets and `natGatewayRoutes`. Priority 3001 sends DNS only to the
  VPC resolver. The default subnet's ACL also allows the private subnet, so the two reach each other.
- **Instances** in the private subnet run on the NAT gateway node (node label `openinfra.dev/nat-gateway`),
  so the machine that reaches the internet shares hardware with nothing else that the private subnet's
  routes do not cover. ECS tasks there may run on any node: their traffic still leaves through the gateway
  node.
- **Without a NAT gateway node** the private subnet is still rendered, with no NAT and no routes out: the
  gateway is `failed` and its routes `blackhole`, so nothing leaves.

## Setting up

1. **The node.** Pick a node with a fixed address that hosts nothing that must stay off the internet path,
   set `networking.natGateway.node` in `config.yaml`, and run `install.sh` (or apply what it applies: the
   node label `openinfra.dev/nat-gateway=true`, the `openinfra-nat-gateway` EnvironmentConfig with
   `natGatewayNode`, and the ConfigMap `open-infra-aws-shim/openinfra-nat-gateways` with
   `NAT_GATEWAY_ADDRESS`, the node's address).
2. **The account.** Give its default VPC a public subnet, the NAT gateway and the private subnet:

   ```sh
   kubectl patch account.organizations.openinfra.dev 111122223333 --type merge -p '{"spec":{"defaultVpc":{
     "publicSubnet":{"subnetCidr":"172.31.240.0/24"},
     "natGateway":true,
     "privateSubnet":{"subnetCidr":"172.31.241.0/24","natGatewayRoutes":["198.51.100.7/32"]}}}}'
   ```

   The private subnet's CIDR must not overlap any account's default subnet, and cannot change once set;
   `CreateAccount` skips the /20 it is in. A route names an internet destination only: the Account refuses
   private, shared, loopback, link-local and multicast ranges, and so `0.0.0.0/0`.
3. **Your site's router.** The gateway's traffic leaves the node's network interface with the node's address,
   to your site's router, which translates it again to its own internet address. If the traffic must leave
   by one uplink, route it there on the router, matching the node's address and the destinations. Where the
   router supports it, also make it drop the traffic when that uplink is down rather than fail over.

## Checking it

- `kubectl get subnet default-vpc-<account>-private -o yaml`: `natOutgoing: true`, `gatewayType: centralized`,
  `status.activateGateway` the NAT gateway node, and the ACLs above.
- `probe/aws-shim-ec2-nat-gateway.sh` (`ACCOUNT_ID`, `ROUTED_URL` an http URL at a routed destination): the
  gateway and its routes as EC2 reports them, a task in the private subnet reaching the routed destination
  and nothing else, and a principal with no policy refused.

## Removing it

Remove the account's `natGatewayRoutes` to close the routes, or `privateSubnet` (once no instance or task
uses it) to remove the subnet. Unset `networking.natGateway.node` and remove the node label to take the
gateway out of service for every account.
