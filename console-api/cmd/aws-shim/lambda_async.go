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
	_, _ = js.AddStream(&nats.StreamConfig{
		Name: asyncStream, Subjects: []string{asyncSubjectAll},
		Storage: nats.FileStorage, Discard: nats.DiscardOld, MaxBytes: 256 * 1024 * 1024,
	})
	_, _ = js.AddStream(&nats.StreamConfig{
		Name: "LAMBDA_ASYNC_DLQ", Subjects: []string{"dlq.lambda.async.>"},
		Storage: nats.FileStorage, Discard: nats.DiscardOld, MaxBytes: 64 * 1024 * 1024,
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
			a.deliver(ctx, m)
		}
	}
}

// deliver POSTs one queued invocation to its function. 2xx → ack; otherwise nak to retry until
// MaxDeliver, then dead-letter and terminate so it is never redelivered.
func (a *asyncInvoker) deliver(ctx context.Context, m *nats.Msg) {
	name := m.Header.Get("X-Fn-Name")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.urlFor(name), bytes.NewReader(m.Data))
	if err != nil {
		_ = m.Nak()
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
		a.logger.Warn("lambda async DEAD-LETTER", "function", name, "attempts", attempts)
		dlq := nats.NewMsg("dlq." + m.Subject)
		dlq.Data = m.Data
		dlq.Header = m.Header
		_, _ = a.js.PublishMsg(dlq)
		_ = m.Term() // stop redelivery permanently
		return
	}
	a.logger.Warn("lambda async delivery failed, will retry", "function", name, "attempt", attempts)
	_ = m.Nak()
}

// Close drains the NATS connection.
func (a *asyncInvoker) Close() { _ = a.nc.Drain() }
