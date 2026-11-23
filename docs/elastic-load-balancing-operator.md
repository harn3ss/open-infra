# Elastic Load Balancing: operator guide

*This is an operator guide: it speaks of MetalLB, Services and Kubernetes resources, which customers never
see. What a customer gets is in [Elastic Load Balancing](elastic-load-balancing.md).*

A network load balancer is served by the aws-shim (`elbv2.go`). Each load balancer is a `LoadBalancer`
Service in the shim's namespace (`open-infra-aws-shim`), named `elb-<account>-<id>`. It has no selector, and
its ports are the load balancer's listeners'. Its endpoints are EndpointSlices the shim writes from its
targets: each running instance's address and node. The Service keeps the client's address
(`externalTrafficPolicy: Local`, announced from the nodes the targets run on) and opens no node ports
(`allocateLoadBalancerNodePorts: false`). The account's records (load balancers, target groups, listeners)
are the Secret `elbv2-<account>` beside the CloudFormation stack records.

Every 20 seconds the shim brings each account's objects in line with its records: endpoints follow instances
as they stop, start and migrate, a terminated instance leaves its target groups, and the objects of a
deleted load balancer, or of an account whose home namespace is gone, are removed.

## Setting up

1. **Addresses.** Load balancers take their addresses from a MetalLB `IPAddressPool`. Use a routed pool the
   clients reach (with MetalLB BGP, the pool your BGP advertisement announces), so an address is announced
   only from the nodes running its targets. Set it in `config.yaml` and run `install.sh`, which writes it
   into the `openinfra-load-balancers` ConfigMap the shim reads (`ELB_ADDRESS_POOL`):

   ```yaml
   networking:
     loadBalancers:
       addressPool: <pool name>
   ```

   Unset, MetalLB's default pool is used.

2. **A public subnet** for an account whose default VPC has no internet gateway
   (`spec.defaultVpc.internetGateway: false`). The CIDR is inside `172.31.0.0/16` and outside the account's
   default subnet. It takes no addresses on the cluster network: it is where the account's load balancers
   are placed in EC2's view.

   ```sh
   kubectl patch accounts.organizations.openinfra.dev <account id> --type merge \
     -p '{"spec":{"defaultVpc":{"publicSubnet":{"subnetCidr":"172.31.240.0/24"}}}}'
   ```

   EC2 then lists an internet gateway attached to the VPC, the public subnet with its own route table
   (`0.0.0.0/0` to that gateway), and the default subnet's main route table still without that route. The
   default subnet's network ACL keeps its instances inside the platform, as before. They answer the clients a
   load balancer brings them: the replies leave as the established traffic of those clients' connections.

3. **Permissions.** The shim's Role `aws-shim-elbv2` (in its own namespace) writes the Services and
   EndpointSlices. After the Role is first applied, regenerate the control-plane corpus, as after any shim
   RBAC change ([authz webhook](authz-webhook.md)).

## Checking a load balancer

```sh
kubectl -n open-infra-aws-shim get svc,endpointslices -l openinfra.dev/elbv2-account=<account id>
```

The Service's external IP is the load balancer's address. An EndpointSlice with no endpoints means no
registered instance is running. A client the target's security group does not admit is dropped by the
group's network policy, which sees the client's own address.

## Live proof

`probe/aws-shim-elbv2-nlb.sh` (passing live) creates a throwaway member account with a default VPC without its internet
gateway and a public subnet, then runs the whole flow through the AWS CLI from LAN clients outside the
cluster. It needs two such clients (`LAN_CLIENT_A`, `LAN_CLIENT_B`); `probe/lan-client-netns.sh` makes one
on a node, in a network namespace with its own DHCP lease.
