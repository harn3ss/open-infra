import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPolicyDocument, formatAccountId, statementCount } from "./policy-document.ts";

test("an AWS policy document is checked the way IAM's editor checks it", () => {
  assert.equal(
    checkPolicyDocument(JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }] })),
    null,
  );
  assert.match(checkPolicyDocument("{") ?? "", /Not valid JSON/);
  assert.match(checkPolicyDocument("[]") ?? "", /JSON object/);
  assert.match(checkPolicyDocument(JSON.stringify({ Version: "2012-10-17" })) ?? "", /at least one Statement/);
  assert.match(checkPolicyDocument(JSON.stringify({ Statement: [{ Effect: "Maybe", Action: "s3:*" }] })) ?? "", /Effect/);
  assert.match(checkPolicyDocument(JSON.stringify({ Statement: [{ Effect: "Allow" }] })) ?? "", /Action or NotAction/);
  assert.match(checkPolicyDocument(JSON.stringify({ Version: "2020-01-01", Statement: [] })) ?? "", /Version/);
  // A single statement object is valid, as IAM accepts it.
  assert.equal(checkPolicyDocument(JSON.stringify({ Statement: { Effect: "Deny", NotAction: "iam:*", Resource: "*" } })), null);
});

test("statements are counted, and an account id is grouped as the AWS console shows it", () => {
  assert.equal(statementCount(JSON.stringify({ Statement: [{}, {}] })), 2);
  assert.equal(statementCount("nope"), 0);
  assert.equal(formatAccountId("000000000000"), "0000-0000-0000");
  assert.equal(formatAccountId("123"), "123");
});
