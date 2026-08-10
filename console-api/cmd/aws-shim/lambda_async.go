package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

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
	nc         *nats.Conn
	js         nats.JetStreamContext
	client     *http.Client
	urlFor     func(name string) string // function URL builder (injectable for tests)
	maxDeliver int
	logger     *slog.Logger
}

const (
	asyncStream     = "LAMBDA_ASYNC"
	asyncSubjectAll = "lambda.async.>"
	asyncSubjectPre = "lambda.async." // per-function subject: lambda.async.<name>
	asyncDurable    = "lambda-async-worker"
	asyncAckWait    = 2 * time.Minute // > the delivery client timeout, so no redelivery mid-POST
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
		Name: "LAMBDA_ASYNC_DLQ", Subjects: []string{"dlq.lambda.async.>"},
		Storage: nats.FileStorage, Discard: nats.DiscardNew, MaxBytes: 64 * 1024 * 1024,
	})
	if maxDeliver < 1 {
		maxDeliver = 3
	}
	return &asyncInvoker{
		nc: nc, js: js, client: &http.Client{Timeout: 60 * time.Second},
		urlFor:     func(name string) string { return "http://" + name + "." + fnNS + "." + svcSuffix + "/" },
		maxDeliver: maxDeliver, logger: logger,
	}, nil
}

// publish enqueues an async invocation. The function name + content-type ride as message headers; the
// payload is the message body. Returns an error only if the durable enqueue itself fails (the caller
// then reports a 500 rather than a false 202).
func (a *asyncInvoker) publish(name, contentType string, payload []byte, requestID string) error {
	msg := nats.NewMsg(asyncSubjectPre + name)
	msg.Data = payload
	msg.Header.Set("X-Fn-Name", name)
	if contentType != "" {
		msg.Header.Set("Content-Type", contentType)
	}
	if requestID != "" {
		msg.Header.Set("X-Amzn-Request-Id", requestID)
	}
	_, err := a.js.PublishMsg(msg)
	return err
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
	dctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(dctx, http.MethodPost, a.urlFor(name), bytes.NewReader(m.Data))
	if err != nil {
		// A malformed name can never build a valid URL — retrying is pointless; dead-letter now rather
		// than nak-loop forever (there is no consumer-level MaxDeliver backstop).
		a.deadLetter(m, name, "unbuildable request URL: "+err.Error())
		return
	}
	if ct := m.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := a.client.Do(req)
	delivered := err == nil && resp.StatusCode < http.StatusBadRequest
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
	dlq := nats.NewMsg("dlq." + m.Subject)
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
