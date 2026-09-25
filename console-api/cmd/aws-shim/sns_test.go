package main

import (
	"regexp"
	"testing"
)

func TestNameFromArn(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sns:us-east-1:open-infra:orders": "orders",
		"arn:aws:sqs:us-east-1:open-infra:jobs":   "jobs",
		"bare":                                    "bare",
	}
	for in, want := range cases {
		if got := nameFromArn(in); got != want {
			t.Errorf("nameFromArn(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTopicArnOfSub(t *testing.T) {
	sub := "arn:aws:sns:us-east-1:open-infra:orders:deadbeef01"
	want := "arn:aws:sns:us-east-1:open-infra:orders"
	if got := topicArnOfSub(sub); got != want {
		t.Errorf("topicArnOfSub(%q)=%q want %q", sub, got, want)
	}
}

func TestUUIDLikeShape(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for i := 0; i < 5; i++ {
		if u := uuidLike(); !re.MatchString(u) {
			t.Errorf("uuidLike produced a non-UUID shape: %q", u)
		}
	}
}

func TestBoolStr(t *testing.T) {
	if boolStr(true) != "true" || boolStr(false) != "false" {
		t.Error("boolStr wrong")
	}
}
