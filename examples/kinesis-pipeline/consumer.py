"""A tiny Kinesis consumer for open-infra (via the AWS-SDK shim).

Reads a shard from TRIM_HORIZON (the beginning of the retained window) in order, looping on the shard
iterator exactly as the KCL and real applications do, and prints each record with its SequenceNumber and how
far behind latest it is. Run it twice to see replay: TRIM_HORIZON re-reads from the start — the whole point
of Kinesis over a queue. Uses boto3 unmodified; only the endpoint is pointed at the shim.

    AWS_ENDPOINT_URL=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566 \
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
    python consumer.py my-stream
"""
import sys
import boto3


def main():
    stream = sys.argv[1] if len(sys.argv) > 1 else "demo-stream"
    k = boto3.client("kinesis")

    shards = k.list_shards(StreamName=stream)["Shards"]
    for shard in shards:
        sid = shard["ShardId"]
        it = k.get_shard_iterator(StreamName=stream, ShardId=sid, ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        empty_polls = 0
        while it:
            out = k.get_records(ShardIterator=it, Limit=100)
            for r in out["Records"]:
                print(f"[{sid}] seq={r['SequenceNumber']} behind={out['MillisBehindLatest']}ms "
                      f"key={r['PartitionKey']} data={r['Data'].decode(errors='replace')}")
            it = out.get("NextShardIterator")
            if not out["Records"]:
                empty_polls += 1
                if empty_polls >= 2:  # caught up: stop tailing this shard (a real tail would keep polling)
                    break


if __name__ == "__main__":
    main()
