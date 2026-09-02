// Package tracing wires OpenTelemetry distributed tracing for the console-api
// services (the BFF and the aws-shim, which share this module). It is OPT-IN:
// with OTEL_EXPORTER_OTLP_ENDPOINT unset, Init installs no exporter and the
// otelhttp handlers add negligible overhead; with it set (e.g. the Tempo OTLP
// receiver at tempo.monitoring.svc:4317), spans export over OTLP/gRPC. W3C
// traceparent propagation is always installed so an inbound trace context is
// honored and stitched across services regardless of export.
package tracing

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Init sets the global W3C propagator and, when an OTLP endpoint is configured,
// a batching TracerProvider exporting to it. It returns a shutdown func to flush
// spans on exit (a no-op when tracing is disabled).
func Init(ctx context.Context, service string) (func(context.Context) error, error) {
	// Always honor W3C traceparent + baggage, even without an exporter, so an
	// incoming trace context flows through and downstream calls stay stitched.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return func(context.Context) error { return nil }, nil
	}

	// The exporter reads OTEL_EXPORTER_OTLP_ENDPOINT (and the http:// scheme selects
	// an insecure gRPC connection) from the environment per the OTLP spec.
	exp, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(service)))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
