// cfn-response: CloudFormation's response module for inline (Code.ZipFile) custom-resource handlers, as
// open-infra provides it. The interface is the one AWS documents:
//
//   const response = require("cfn-response");
//   response.send(event, context, response.SUCCESS, responseData, physicalResourceId, noEcho);
//
// send PUTs the response to the event's ResponseURL, as AWS's module does, over http or https as the URL
// says, then ends the invocation with context.done(). It also returns a Promise that settles when the PUT
// has completed, for a handler that awaits it.
"use strict";

exports.SUCCESS = "SUCCESS";
exports.FAILED = "FAILED";

exports.send = function (event, context, responseStatus, responseData, physicalResourceId, noEcho) {
  return new Promise(function (resolve, reject) {
    var finished = false;
    function finish(err) {
      if (finished) return;
      finished = true;
      if (context && typeof context.done === "function") context.done();
      if (err) reject(err);
      else resolve();
    }
    try {
      var stream = (context && context.logStreamName) || "";
      var body = JSON.stringify({
        Status: responseStatus,
        Reason: "See the details in CloudWatch Log Stream: " + stream,
        PhysicalResourceId: physicalResourceId || stream,
        StackId: event.StackId,
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        NoEcho: noEcho || false,
        Data: responseData,
      });
      var target = new URL(event.ResponseURL);
      var transport = target.protocol === "http:" ? require("http") : require("https");
      var request = transport.request(
        target,
        { method: "PUT", headers: { "content-type": "", "content-length": Buffer.byteLength(body) } },
        function (res) {
          console.log("Status code: " + res.statusCode);
          res.resume();
          res.on("end", function () { finish(); });
        }
      );
      request.on("error", function (err) {
        console.log("send(..) failed executing https.request(..): " + err);
        finish(err);
      });
      request.write(body);
      request.end();
    } catch (err) {
      console.log("send(..) failed: " + err);
      finish(err);
    }
  });
};
