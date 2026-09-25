# Kinesis pipeline (ordered, replayable streaming)

A minimal target app for the [Kinesis doorway](../../docs/aws-shim.md) on the AWS-SDK shim: a producer that
writes an ordered sequence and a consumer that reads it back in order and can **replay** from the start. It
uses **boto3 unmodified** — only `AWS_ENDPOINT_URL` points at the shim — so an app written for AWS Kinesis
runs against open-infra as-is.

This is what distinguishes Kinesis from the SQS/SNS doorways: records under one `PartitionKey` keep strict
order with monotonic `SequenceNumber`s, and a `TRIM_HORIZON` iterator re-reads the whole retained window
(replay), which a queue cannot do.

## Run it

```sh
export AWS_ENDPOINT_URL=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566
export AWS_ACCESS_KEY_ID=<your open-infra access key id>
export AWS_SECRET_ACCESS_KEY=<your secret>

aws kinesis create-stream --stream-name demo --shard-count 2

python producer.py demo orders-42 10     # write 10 ordered events under one key
python consumer.py demo                   # read them back, in order
python consumer.py demo                   # run again → REPLAY: TRIM_HORIZON re-reads from the start
```

The consumer prints each record's `SequenceNumber` and `MillisBehindLatest` (consumer lag), the same fields
the KCL loops on. Ordering holds within a shard; across shards there is no global order (as in AWS).

## Notes

- `PartitionKey` determines the shard (a stable hash), so all records for one key stay ordered together.
- Retention defaults to 24h; records replay within that window and are trimmed after it.
- Supported: `CreateStream`/`DescribeStream`/`ListStreams`/`DeleteStream`, `PutRecord`/`PutRecords`,
  `GetShardIterator`/`GetRecords`/`ListShards`, retention changes. Resharding, enhanced fan-out, and KCL lease
  coordination are out of scope (see the shim docs).
