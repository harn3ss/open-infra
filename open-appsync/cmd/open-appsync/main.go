// Command open-appsync is open-infra's resolver-first, VTL-faithful AWS AppSync engine (the engine
// the aws-shim's `appsync` service fronts). It loads a declarative resolver config and serves GraphQL
// over HTTP at POST /graphql. See open-appsync/README.md.
//
// UN-PROVEN as a full AppSync: slice 1 is VTL over one DynamoDB-style data source. Un-configured or
// un-fronted paths fail honestly; nothing is faked.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/k8sauth"
	"github.com/harn3ss/open-infra/open-appsync/internal/metrics"
	"github.com/harn3ss/open-infra/open-appsync/internal/server"
	"github.com/harn3ss/open-infra/open-appsync/internal/subscription"
	"github.com/harn3ss/open-infra/open-appsync/internal/tracing"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("open-appsync exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	configDir := getenv("CONFIG_DIR", "/etc/open-appsync")

	// FerretDB (Mongo wire) backs "dynamodb" data sources. Optional: if MONGO_URI is unset the engine
	// serves only "memory" data sources (an ephemeral demo) and errors on a dynamodb source.
	var mongoDB *mongo.Database
	if uri := os.Getenv("MONGO_URI"); uri != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
		if err != nil {
			return err
		}
		mongoDB = client.Database(getenv("MONGO_DB", "open_appsync"))
		logger.Info("connected to FerretDB", slog.String("db", mongoDB.Name()))
	}

	// Field-level authz: in-cluster, enforce requirements via impersonated SubjectAccessReviews
	// against the shared RBAC boundary. Out of cluster (dev), fall back to no enforcement and say so —
	// a field's Requirement is then not checked, so this must be logged loudly, not silent.
	var authorizer authz.Authorizer = authz.AllowAll{}
	if sar, err := k8sauth.InCluster(); err == nil {
		authorizer = sar
		logger.Info("field-level authorization ENABLED (SubjectAccessReview against cluster RBAC)")
	} else {
		logger.Warn("field-level authorization NOT enforced — no in-cluster RBAC; field Requirements are ignored", slog.String("reason", err.Error()))
	}
	engineOpts := []graphql.Option{graphql.WithAuthorizer(authorizer)}

	// Subscriptions: the bus is the durable JetStream bus when NATS_URL is set (multi-node,
	// reconnect/resume across a node kill — the path the chaos bar exercises), otherwise a single-node
	// in-memory bus. If the config declares subscriptions, wire the publisher so a mutation pushes to
	// its subscribers, and serve the graphql-transport-ws WebSocket below.
	var bus subscription.Bus = subscription.NewMemBus()
	if uri := os.Getenv("NATS_URL"); uri != "" {
		jsb, err := subscription.NewJetStreamBus(uri, getenv("NATS_STREAM", "open_appsync_subscriptions"), getenv("NATS_SUBJECT_PREFIX", "sub"))
		if err != nil {
			return err
		}
		bus = jsb
		logger.Info("subscriptions using durable NATS JetStream bus", slog.String("nats", uri))
	}
	mgr, publisher, err := server.LoadSubscriptions(configDir, bus, authorizer)
	if err != nil {
		return err
	}
	if mgr != nil {
		engineOpts = append(engineOpts, graphql.WithPublisher(publisher))
	}

	engine, err := server.Load(configDir, mongoDB, engineOpts...)
	if err != nil {
		return err
	}

	// Distributed tracing (#67): opt-in via OTEL_EXPORTER_OTLP_ENDPOINT (Tempo). W3C
	// traceparent is honored either way, so a trace from the aws-shim stitches through.
	shutdownTracing, err := tracing.Init(context.Background(), "open-appsync")
	if err != nil {
		logger.Warn("tracing init failed; continuing without traces", slog.String("error", err.Error()))
	} else {
		defer func() { _ = shutdownTracing(context.Background()) }()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Prometheus metrics for in-cluster scraping (the platform's kube-prometheus-stack picks this up
	// via a ServiceMonitor). Same :8080 listener as /graphql — the metrics carry no secrets (bounded
	// labels, counts + latencies only). A future engine NetworkPolicy must allow the monitoring namespace.
	mux.Handle("/metrics", metrics.Handler())
	// API-key authentication (@aws_api_key): load key→identity from the mounted Secret file, if any.
	// THE KEY IS AN IDENTITY — each key impersonates a k8s principal (see server.LoadAPIKeys). Path via
	// APPSYNC_API_KEYS_FILE (the composition mounts the API's Secret there).
	apiKeys, err := server.LoadAPIKeys(os.Getenv("APPSYNC_API_KEYS_FILE"))
	if err != nil {
		logger.Error("load api keys", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if len(apiKeys) > 0 {
		logger.Info("api-key auth enabled", slog.Int("keys", len(apiKeys)))
	}
	mux.HandleFunc("/graphql", server.Handler(engine, server.WithAPIKeys(apiKeys)))
	// Authoring aid: render a resolver against a sample $ctx without deploying it.
	mux.HandleFunc("/test-resolver", server.TestResolverHandler())
	// Subscriptions over graphql-transport-ws, when the config declares any.
	if mgr != nil {
		if err := mgr.Start(context.Background()); err != nil {
			return err
		}
		defer mgr.Stop()
		mux.HandleFunc("/graphql-ws", server.SubscriptionHandler(mgr))
		logger.Info("subscriptions enabled (graphql-transport-ws at /graphql-ws)")
	}

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: otelhttp.NewHandler(mux, "open-appsync"), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("open-appsync listening", slog.String("addr", addr), slog.String("version", version),
			slog.String("configDir", configDir), slog.Bool("ferretdb", mongoDB != nil))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func logLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
