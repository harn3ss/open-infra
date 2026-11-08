"""cfnresponse: CloudFormation's response module for inline (Code.ZipFile) custom-resource handlers, as
open-infra provides it. The interface is the one AWS documents:

    import cfnresponse
    cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, physicalResourceId)

send PUTs the response to the event's ResponseURL, as AWS's module does.
"""
import json
import urllib.request

SUCCESS = "SUCCESS"
FAILED = "FAILED"


def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False, reason=None):
    stream = getattr(context, "log_stream_name", "") or ""
    body = json.dumps({
        "Status": responseStatus,
        "Reason": reason or "See the details in CloudWatch Log Stream: {}".format(stream),
        "PhysicalResourceId": physicalResourceId or stream,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": noEcho,
        "Data": responseData,
    }).encode("utf-8")
    req = urllib.request.Request(event["ResponseURL"], data=body, method="PUT",
                                 headers={"Content-Type": "", "Content-Length": str(len(body))})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            print("Status code:", resp.status)
    except Exception as e:
        print("send(..) failed executing http.request(..):", e)
