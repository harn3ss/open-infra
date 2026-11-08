package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/nats-io/nats.go"
)

// asyncInvoker delivers AWS Lambda "Event" (asynchronous) invocations DURABLY. On an Event invoke the
// shim publishes the payload to a JetStream stream and returns 202 immediately; this background worker
// consumes and POSTs each to its function, retrying on failure and dead-lettering after MaxDeliver —
// the same durable-delivery pattern apply-sink uses. Persistence means an invocation survives a shim
// restart, and a durable pull consumer lets multiple shim replicas share the delivery load.
//
// Enabled only when the shim has NATS (NATS_URL). Without it, Event invocations are refused honestly
// rather than silently dropped (there is no durable place to queue them).
type asyncInvoker struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	client *http.Client
	urlFor func(name, ns string) string // function URL builder ("" ns = the Lambda API's); injectable for tests
	// timeoutFor is a function's timeout, which a delivery waits for (lambda_timeout.go); nil = the default.
	// coldStart is added to it.
	timeoutFor func(ns, name string) time.Duration
	coldStart  time.Duration
	// progressEvery is how often a delivery tells JetStream it is still working (so a long function is never
	// redelivered mid-run).
	progressEvery time.Duration
	maxDeliver    int
	logger        *slog.Logger
}

const (
	asyncStream     = "LAMBDA_ASYNC"
	asyncSubjectAll = "lambda.async.>"
	asyncSubjectPre = "lambda.async." // per-function work subject: lambda.async.<name> (a member account's: lambda.async.<account>.<name>)
	asyncDLQStream  = "LAMBDA_ASYNC_DLQ"
	asyncDLQAll     = "lambda.dlq.>"
	// Dead-letter subject. Deliberately NOT under "dlq.*" (that overlaps the platform-wide "dlq.>"
	// stream apply-sink owns — JetStream forbids overlapping stream subjects, so our DLQ stream would
	// silently fail to create and our dead-letters would pollute a shared stream) and NOT under
	// "lambda.async.*" (that would be re-consumed by the work stream — an infinite dead-letter loop).
	asyncDLQPre  = "lambda.dlq." // per-function dead-letter subject: lambda.dlq.<name> (a member account's: lambda.dlq.<account>.<name>)
	asyncDurable = "lambda-async-worker"
	// asyncAckWait: a delivery in flight signals progress every quarter of it (deliver), so a function
	// running up to its own timeout is never redelivered mid-run; a shim that dies mid-delivery has its
	// message redelivered this long after.
	asyncAckWait = 2 * time.Minute
)

// newAsyncInvoker connects to NATS, ensures the async work stream + a DLQ stream exist, and returns a
// ready invoker. A connection failure is returned so the caller can run without async rather than crash.
func newAsyncInvoker(url, fnNS, svcSuffix string, maxDeliver int, logger *slog.Logger) (*asyncInvoker, error) {
	nc, err := nats.Connect(url, nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, err
	}
	// The async work stream and the dead-letter stream. AddStream on an existing stream returns an
	// "already in use" error we intentionally ignore (idempotent setup across replicas/restarts).
	//
	// WorkQueuePolicy: a message leaves the stream once the (single) durable worker Acks or Terms it, so
	// only genuinely-pending work occupies the byte budget — delivered and dead-lettered invocations do
	// not linger. DiscardNew: when a real backlog exceeds the cap, PublishMsg is REJECTED (publish()
	// returns the error → the handler returns 500), rather than DiscardOld silently evicting the oldest
	// still-undelivered invocation that already got a 202. That is the difference between honest
	// backpressure and silent loss of accepted work. (NB: NATS cannot change Retention on an existing
	// stream; a stream created by an older build must be deleted to pick this up — the async feature is
	// new, so no such stream exists yet.)
	_, _ = js.AddStream(&nats.StreamConfig{
		Name: asyncStream, Subjects: []string{asyncSubjectAll},
		Storage: nats.FileStorage, Retention: nats.WorkQueuePolicy, Discard: nats.DiscardNew,
		MaxBytes: 256 * 1024 * 1024,
	})
	// The DLQ also refuses-when-full: dropping the oldest dead-letters would defeat the last-resort net.
	_, _ = js.AddStream(&nats.StreamConfig{
		Name: asyncDLQStream, Subjects: []string{asyncDLQAll},
		Storage: nats.FileStorage, Discard: nats.DiscardNew, MaxBytes: 64 * 1024 * 1024,
	})
	if maxDeliver < 1 {
		maxDeliver = 3
	}
	return &asyncInvoker{
		// No client-wide timeout: each delivery waits for its function's own (lambda_timeout.go).
		nc: nc, js: js, client: &http.Client{}, coldStart: invokeColdStartAllowance, progressEvery: asyncAckWait / 4,
		urlFor: func(name, ns string) string {
			if ns == "" {
				ns = fnNS
			}
			return "http://" + name + "." + ns + "." + svcSuffix + "/"
		},
		maxDeliver: maxDeliver, logger: logger,
	}, nil
}

// publish enqueues an async invocation. The function name, its namespace (where the caller's right to
// invoke it was checked; "" = the Lambda API's) and content-type ride as message headers; the payload is
// the message body. Returns an error only if the durable enqueue itself fails (the caller then reports a
// 500 rather than a false 202). It is the management account's function's (publishFor names the account).
func (a *asyncInvoker) publish(name, ns, contentType string, payload []byte, requestID string) error {
	return a.publishFor("", name, ns, contentType, payload, requestID)
}

// publishFor is publish for the function of account ("" or the management account's: exactly publish).
// A member account's invocation rides its own subject (lambda.async.<account>.<name>) and names its
// account (X-Fn-Account), so its dead-letter is the account's too, never the management account's
// function's of the same name.
func (a *asyncInvoker) publishFor(account, name, ns, contentType string, payload []byte, requestID string) error {
	_, err := a.js.PublishMsg(asyncMsg(account, name, ns, contentType, payload, requestID))
	return err
}

// publishVersionFor is publishFor for one published version of the function (version "" = $LATEST): its
// delivery goes to that version (lambda_versions.go), as Lambda runs an asynchronous invocation of a
// qualified function. invokedARN is the ARN the caller invoked it by, which the handler's context
// reports ("" = none given).
func (a *asyncInvoker) publishVersionFor(account, name, ns, version, invokedARN, contentType string, payload []byte, requestID string) error {
	msg := asyncMsg(account, name, ns, contentType, payload, requestID)
	if version != "" {
		msg.Header.Set("X-Fn-Version", version)
	}
	if invokedARN != "" {
		msg.Header.Set("X-Fn-Invoked-Arn", invokedARN)
	}
	_, err := a.js.PublishMsg(msg)
	return err
}

// asyncMsg is the queued invocation of account's function name in ns.
func asyncMsg(account, name, ns, contentType string, payload []byte, requestID string) *nats.Msg {
	member := !awsidentity.Current().IsManagement(account)
	msg := nats.NewMsg(asyncSubject(account, name))
	msg.Data = payload
	msg.Header.Set("X-Fn-Name", name)
	if member {
		msg.Header.Set("X-Fn-Account", account)
	}
	if ns != "" {
		msg.Header.Set("X-Fn-Namespace", ns)
	}
	if contentType != "" {
		msg.Header.Set("Content-Type", contentType)
	}
	if requestID != "" {
		msg.Header.Set("X-Amzn-Request-Id", requestID)
	}
	return msg
}

// asyncSubject is the work subject of account's function name: lambda.async.<name> for the management
// account (as always), lambda.async.<account>.<name> for a member account's.
func asyncSubject(account, name string) string {
	if awsidentity.Current().IsManagement(account) {
		return asyncSubjectPre + name
	}
	return asyncSubjectPre + account + "." + name
}

// asyncDLQSubject is the dead-letter subject of account's function name: lambda.dlq.<name> for the
// management account (as always), lambda.dlq.<account>.<name> for a member account's.
func asyncDLQSubject(account, name string) string {
	if awsidentity.Current().IsManagement(account) {
		return asyncDLQPre + name
	}
	return asyncDLQPre + account + "." + name
}

// dlqAccount is the account a queued invocation's X-Fn-Account header names: "" (the management account)
// when it has none, as every invocation queued before accounts; "unknown" for one that is no account id,
// so a malformed header never lands on the management account's subject nor builds an invalid one.
func dlqAccount(h string) string {
	switch {
	case h == "":
		return ""
	case len(h) == 12 && strings.Trim(h, "0123456789") == "":
		return h
	}
	return "unknown"
}

// run is the delivery loop: pull batches, POST each to its function, ack on success, nak to retry, and
// dead-letter (publish to dlq.<subject> + terminate) after MaxDeliver. Blocks until ctx is cancelled.
func (a *asyncInvoker) run(ctx context.Context) {
	sub, err := a.js.PullSubscribe(asyncSubjectAll, asyncDurable,
		nats.BindStream(asyncStream), nats.AckExplicit(), nats.DeliverAll(), nats.ManualAck(), nats.AckWait(asyncAckWait))
	if err != nil {
		a.logger.Error("lambda async worker: subscribe failed — async delivery disabled", "error", err.Error())
		return
	}
	a.logger.Info("lambda async worker started")
	for {
		if ctx.Err() != nil {
			return
		}
		msgs, err := sub.Fetch(50, nats.MaxWait(5*time.Second))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				continue // normal empty poll
			}
			a.logger.Warn("lambda async fetch", "error", err.Error())
			time.Sleep(time.Second)
			continue
		}
		for _, m := range msgs {
			if ctx.Err() != nil {
				// Shutting down: return un-started work for redelivery rather than aborting it, and don't
				// start new deliveries. In-flight deliveries use their own context (below), so they finish.
				_ = m.Nak()
				continue
			}
			a.deliver(m)
		}
	}
}

// deliver POSTs one queued invocation to its function. It uses its OWN bounded context — NOT the
// shutdown context — so a SIGTERM never aborts an in-flight function call mid-delivery (which would
// leave it un-acked and cause a redelivery / double-invoke on the next boot). 2xx → ack; a transient
// failure → delayed (backing-off) nak until MaxDeliver; then dead-letter — but only Term once the
// dead-letter is durably stored (see deadLetter), so a failed DLQ write never drops the invocation.
func (a *asyncInvoker) deliver(m *nats.Msg) {
	name := m.Header.Get("X-Fn-Name")
	timeout := defaultFunctionTimeout
	if a.timeoutFor != nil {
		timeout = a.timeoutFor(m.Header.Get("X-Fn-Namespace"), name)
	}
	dctx, cancel := context.WithTimeout(context.Background(), timeout+a.coldStart)
	defer cancel()
	// Keep the message ours while the function runs: JetStream redelivers one not acked within AckWait.
	if a.progressEvery > 0 {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			t := time.NewTicker(a.progressEvery)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					_ = m.InProgress()
				}
			}
		}()
	}
	// A published version is delivered to its own address (v<version>-<name>, lambda_versions.go).
	host := name
	if v := m.Header.Get("X-Fn-Version"); v != "" {
		if !versionNumberRe.MatchString(v) {
			a.deadLetter(m, name, "the queued invocation names no valid function version")
			return
		}
		host = versionTagHost(v, name)
	}
	req, err := http.NewRequestWithContext(dctx, http.MethodPost, a.urlFor(host, m.Header.Get("X-Fn-Namespace")), bytes.NewReader(m.Data))
	if err != nil {
		// A malformed name can never build a valid URL — retrying is pointless; dead-letter now rather
		// than nak-loop forever (there is no consumer-level MaxDeliver backstop).
		a.deadLetter(m, name, "unbuildable request URL: "+err.Error())
		return
	}
	if ct := m.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	// Lambda's asynchronous invoke passes the payload to the handler as sent (direct-invoke, not the API
	// Gateway proxy mapping), and a function error is a failed attempt, retried and then dead-lettered.
	req.Header.Set("X-Openinfra-Invoke", "direct")
	version := m.Header.Get("X-Fn-Version")
	if version == "" {
		version = "$LATEST"
	}
	setInvocationContext(req.Header, m.Header.Get("X-Fn-Invoked-Arn"), version)
	resp, err := a.client.Do(req)
	delivered := err == nil && resp.StatusCode < http.StatusBadRequest && resp.Header.Get("X-Amz-Function-Error") == ""
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if delivered {
		_ = m.Ack()
		return
	}
	attempts := 1
	if md, mErr := m.Metadata(); mErr == nil {
		attempts = int(md.NumDelivered)
	}
	if attempts >= a.maxDeliver {
		a.deadLetter(m, name, "max delivery attempts exhausted")
		return
	}
	// Back off before redelivery so a cold-starting / rolling-deployed function isn't dead-lettered
	// within milliseconds — it is commonly Ready seconds later (AWS async spaces retries over minutes).
	delay := time.Duration(attempts) * 10 * time.Second
	a.logger.Warn("lambda async delivery failed, will retry", "function", name, "attempt", attempts,
		"retryInS", int(delay.Seconds()))
	_ = m.NakWithDelay(delay)
}

// deadLetter publishes the invocation to its DLQ subject and terminates redelivery ONLY on a successful
// DLQ write. If the DLQ write fails (quorum loss, missing stream, full DLQ) it naks to keep the message
// for a later retry — a failed dead-letter must never silently drop an accepted invocation.
func (a *asyncInvoker) deadLetter(m *nats.Msg, name, reason string) {
	if name == "" {
		name = "unknown" // never build a trailing-dot (invalid) subject
	}
	// The function's account's dead-letter subject: the account the invocation was queued in.
	dlq := nats.NewMsg(asyncDLQSubject(dlqAccount(m.Header.Get("X-Fn-Account")), name))
	dlq.Data = m.Data
	dlq.Header = m.Header
	if _, err := a.js.PublishMsg(dlq); err != nil {
		a.logger.Error("lambda async DLQ publish failed — keeping the invocation for retry",
			"function", name, "reason", reason, "error", err.Error())
		_ = m.NakWithDelay(30 * time.Second)
		return
	}
	a.logger.Warn("lambda async DEAD-LETTER", "function", name, "reason", reason)
	_ = m.Term() // durably dead-lettered — now stop redelivery permanently
}

// Close drains the NATS connection.
func (a *asyncInvoker) Close() { _ = a.nc.Drain() }
