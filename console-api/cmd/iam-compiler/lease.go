package main

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// metavFor is the leader-election Lease's identity.
func metavFor(name, ns string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name, Namespace: ns} }
