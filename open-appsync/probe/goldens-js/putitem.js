import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'PutItem',
    key: { id: util.dynamodb.toDynamoDB(util.autoId()) },
    attributeValues: util.dynamodb.toMapValues(ctx.args.input),
  };
}

export function response(ctx) {
  return ctx.result;
}
