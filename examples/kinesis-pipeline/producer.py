"""A tiny Kinesis producer for open-infra (via the AWS-SDK shim).

Puts an ordered sequence of records under a single PartitionKey so they all land in one shard and keep their
order — the property that makes Kinesis different from SQS. Uses boto3 unmodified; only the endpoint is
pointed at the shim.

    AWS_ENDPOINT_URL=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566 \
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
    python producer.py my-stream orders-42 10
"""
import sys
import boto3


def main():
    stream = sys.argv[1] if len(sys.argv) > 1 else "demo-stream"
    key = sys.argv[2] if len(sys.argv) > 2 else "orders-1"
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    k = boto3.client("kinesis")  # AWS_ENDPOINT_URL points it at the shim
    for i in range(1, count + 1):
        resp = k.put_record(StreamName=stream, PartitionKey=key, Data=f"event-{i}".encode())
        print(f"put event-{i} -> shard={resp['ShardId']} seq={resp['SequenceNumber']}")


if __name__ == "__main__":
    main()
