// Gate #2 for open-appsync introspection: does the REAL GraphQL ecosystem consume our introspection
// result? This is the operability golden — no AWS byte-string to diff against, so the proof is "a real
// tool builds a usable schema from our output, or it fails."
//
// It runs the two things codegen/Apollo/GraphiQL ultimately do under the hood:
//   1. graphql-js  buildClientSchema(introspection)  → a live GraphQLSchema, then printSchema() it.
//   2. @graphql-codegen typescript plugin            → generate TypeScript types from that schema.
// Then it asserts the reconstructed schema + generated types contain what our SDL declared, with the
// wrappers intact ([Todo!]!, ID!, [String!]). Exits non-zero on any miss so the Go gate fails loud.

import { readFileSync } from 'node:fs';
import { buildClientSchema, printSchema, parse } from 'graphql';
import { codegen } from '@graphql-codegen/core';
import * as typescriptPlugin from '@graphql-codegen/typescript';

const path = process.argv[2] || 'introspection.json';
const introspection = JSON.parse(readFileSync(path, 'utf8'));

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
  console.log('  ok —', msg);
}

// 1. buildClientSchema: the exact call graphql-codegen/Apollo make to turn an introspection result into
//    a schema object. If our result is malformed or incomplete, this throws.
let schema;
try {
  schema = buildClientSchema(introspection);
} catch (e) {
  console.error('FAIL: buildClientSchema threw —', e.message);
  process.exit(1);
}
console.log('buildClientSchema: reconstructed a GraphQLSchema from our introspection result');

const sdl = printSchema(schema);
console.log('\n--- printSchema(buildClientSchema(result)) ---\n' + sdl + '\n---');

assert(/type Todo\b/.test(sdl), 'reconstructed schema has `type Todo`');
assert(/enum Priority\b/.test(sdl), 'reconstructed schema has `enum Priority`');
assert(/input CreateTodoInput\b/.test(sdl), 'reconstructed schema has `input CreateTodoInput`');
assert(/scalar AWSDateTime\b/.test(sdl), 'reconstructed schema has custom `scalar AWSDateTime`');
assert(/id:\s*ID!/.test(sdl), 'Todo.id is ID! (NON_NULL wrapper survived)');
assert(/listTodos:\s*\[Todo!\]!/.test(sdl), 'Query.listTodos is [Todo!]! (nested wrappers survived)');
assert(/tags:\s*\[String!\]/.test(sdl), 'Todo.tags is [String!] (list-of-non-null survived)');
assert(/priority:\s*Priority\s*=\s*LOW/.test(sdl), 'CreateTodoInput.priority default LOW survived');
assert(schema.getQueryType()?.name === 'Query', 'query root is Query');
assert(schema.getMutationType()?.name === 'Mutation', 'mutation root is Mutation');
assert(schema.getSubscriptionType()?.name === 'Subscription', 'subscription root is Subscription');

// 2. graphql-codegen: generate real TypeScript types from the reconstructed schema. This is the tool the
//    plan names explicitly — proof the whole codegen path lights up on our introspection.
const ts = await codegen({
  schema: parse(printSchema(schema)),
  documents: [],
  config: {},
  filename: 'types.ts',
  plugins: [{ typescript: {} }],
  pluginMap: { typescript: typescriptPlugin },
});
console.log('\n--- graphql-codegen typescript output (excerpt) ---\n' + ts.slice(0, 600) + '\n---');

assert(/export type Todo = {/.test(ts), 'codegen emitted `export type Todo`');
assert(/export type CreateTodoInput = {/.test(ts), 'codegen emitted `export type CreateTodoInput`');
assert(/Priority =|export enum Priority/.test(ts), 'codegen emitted the Priority enum type');
assert(/export type Mutation = {/.test(ts), 'codegen emitted the Mutation type');

console.log('\nPASS — real GraphQL tooling (buildClientSchema + graphql-codegen) consumed the introspection result.');
