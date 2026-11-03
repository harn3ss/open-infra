package main

import (
	"net/url"
	"testing"
)

// The AWS CLI sends MaxResults=1000 whenever it paginates a describe call, and EC2 caps a value above an
// operation's maximum instead of refusing it, so a plain `aws ec2 describe-volumes` (maximum 500) works.
func TestEC2Page_CapsMaxResultsAboveTheMaximum(t *testing.T) {
	start, end, next, msg, ok := ec2Page(url.Values{"MaxResults": {"1000"}}, 700, 5, 500)
	if !ok {
		t.Fatalf("MaxResults=1000 (the CLI's page size) was refused: %s", msg)
	}
	if start != 0 || end != 500 || next == "" {
		t.Fatalf("want the first 500 of 700 and a next token, got [%d,%d) next=%q", start, end, next)
	}
	start, end, next, _, ok = ec2Page(url.Values{"MaxResults": {"1000"}, "NextToken": {next}}, 700, 5, 500)
	if !ok || start != 500 || end != 700 || next != "" {
		t.Fatalf("want the last 200 and no token, got [%d,%d) next=%q ok=%v", start, end, next, ok)
	}
	if _, end, next, _, ok := ec2Page(url.Values{"MaxResults": {"1000"}}, 3, 5, 500); !ok || end != 3 || next != "" {
		t.Fatalf("a small result set with the CLI's page size: end=%d next=%q ok=%v", end, next, ok)
	}
}

func TestEC2Page_RefusesMaxResultsBelowTheMinimumAndBadTokens(t *testing.T) {
	for _, form := range []url.Values{
		{"MaxResults": {"4"}},
		{"MaxResults": {"x"}},
		{"NextToken": {"!!"}},
	} {
		if _, _, _, msg, ok := ec2Page(form, 10, 5, 500); ok || msg == "" {
			t.Errorf("%v: want a refusal, got ok=%v msg=%q", form, ok, msg)
		}
	}
}
