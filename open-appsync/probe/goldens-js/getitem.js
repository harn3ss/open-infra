import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return { operation: 'GetItem', key: { id: util.dynamodb.toDynamoDB(ctx.args.id) } };
}

export function response(ctx) {
  return ctx.result;
}
