package main

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func vpcTestPod(name string, vpc bool) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "acct", Labels: map[string]string{knativeServiceLabel: "orders"},
		Annotations: map[string]string{lambdaVPCIDAnnotation: "vpc-a", lambdaSubnetsAnnotation: "subnet-a, subnet-b", lambdaSGsAnnotation: "sg-1"}}}
	if vpc {
		p.Labels[lambdaVPCLabel] = "true"
	}
	return p
}

func vpcTestIPObject(name, ip, ns, pod string, created time.Time) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "kubeovn.io/v1", "kind": "IP",
		"metadata": map[string]any{"name": name}, "spec": map[string]any{"ipAddress": ip, "namespace": ns, "podName": pod, "nodeName": "n1"}}}
	u.SetCreationTimestamp(metav1.NewTime(created))
	return u
}

func TestInterfaceForPod(t *testing.T) {
	in, ok := interfaceForPod(vpcTestPod("orders-00001-deployment-abc-xyz", true), "10.17.0.5", "n1", "111122223333", time.Unix(100, 0))
	if !ok {
		t.Fatal("a VPC function's pod has an interface")
	}
	if in.Function != "orders" || in.VpcID != "vpc-a" || len(in.SubnetIDs) != 2 || in.SecurityGroupIDs[0] != "sg-1" {
		t.Fatalf("interface %+v", in)
	}
	if in.SubnetID != "subnet-a" && in.SubnetID != "subnet-b" {
		t.Fatalf("placed in %q, not one of its subnets", in.SubnetID)
	}
	if in.ENI != lambdaENIID("111122223333", "orders", in.SubnetID) || len(in.ENI) != len("eni-")+17 {
		t.Fatalf("eni %q", in.ENI)
	}
	if _, ok := interfaceForPod(vpcTestPod("x", false), "10.17.0.6", "n1", "111122223333", time.Now()); ok {
		t.Fatal("a pod without the Lambda VPC label has no interface")
	}
}

func TestVPCInterfaces_AttachDetachAndHistory(t *testing.T) {
	now := time.Unix(10_000, 0)
	pods := map[string]*corev1.Pod{"p1": vpcTestPod("p1", true), "p2": vpcTestPod("p2", true)}
	v := newVPCInterfaces(nil, func(_ context.Context, _, name string) (*corev1.Pod, error) { return pods[name], nil },
		func(string) string { return "111122223333" }, "", nil)
	v.now = func() time.Time { return now }

	v.attach(context.Background(), vpcTestIPObject("p1.acct", "10.17.0.9", "acct", "p1", now))
	if in, ok := v.At("10.17.0.9", now.Add(time.Minute)); !ok || in.Pod != "p1" {
		t.Fatalf("p1 at its address: %+v %v", in, ok)
	}
	if got := v.Current(); len(got) != 1 || got[0].Pod != "p1" {
		t.Fatalf("current %+v", got)
	}

	// p1 goes; its address is reused by p2 later. A record from p1's lifetime is still p1's.
	now = now.Add(10 * time.Minute)
	v.detach("p1.acct")
	if len(v.Current()) != 0 {
		t.Fatal("a detached interface is not current")
	}
	now = now.Add(5 * time.Minute)
	v.attach(context.Background(), vpcTestIPObject("p2.acct", "10.17.0.9", "acct", "p2", now))
	if in, _ := v.At("10.17.0.9", time.Unix(10_000, 0).Add(2*time.Minute)); in.Pod != "p1" {
		t.Fatalf("a record from p1's lifetime is p1's, got %+v", in)
	}
	if in, _ := v.At("10.17.0.9", now.Add(time.Minute)); in.Pod != "p2" {
		t.Fatalf("a record after the reuse is p2's, got %+v", in)
	}
	if _, ok := v.At("10.17.0.9", time.Unix(1, 0)); ok {
		t.Fatal("nothing had the address long before")
	}

	// Long after p1 detached, it is forgotten.
	now = now.Add(vpcInterfaceKeep + time.Minute)
	v.detach("unknown")
	if in, _ := v.At("10.17.0.9", time.Unix(10_000, 0).Add(2*time.Minute)); in.Pod == "p1" {
		t.Fatal("an interface detached long ago is forgotten")
	}
}

func TestLogGroupOfARN(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:logs:us-east-1:111122223333:log-group:flow-logs":        "111122223333/flow-logs",
		"arn:aws:logs:us-east-1:111122223333:log-group:/vpc/flow-logs:*": "111122223333//vpc/flow-logs",
	} {
		a, n, ok := logGroupOfARN(arn)
		if !ok || a+"/"+n != want {
			t.Errorf("%s: %s %s %v", arn, a, n, ok)
		}
	}
	for _, bad := range []string{"arn:aws:s3:::bucket", "arn:aws:logs:us-east-1:111122223333:destination:x", "nope"} {
		if _, _, ok := logGroupOfARN(bad); ok {
			t.Errorf("%s is not a log group ARN", bad)
		}
	}
}
