import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return util.dynamodb.toDynamoDB(ctx.args.input);
}

export function response(ctx) {
  return ctx.result;
}
