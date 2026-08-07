// Command open-appsync is open-infra's resolver-first, VTL-faithful AWS AppSync engine (the engine
// the aws-shim's `appsync` service fronts). It loads a declarative resolver config and serves GraphQL
// over HTTP at POST /graphql. See open-appsync/README.md and open-infra-open-appsync-handoff.md.
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

	"github.com/harn3ss/open-infra/open-appsync/internal/server"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

	engine, err := server.Load(configDir, mongoDB)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/graphql", server.Handler(engine))
	// Authoring aid (handoff §3): render a resolver against a sample $ctx without deploying it.
	mux.HandleFunc("/test-resolver", server.TestResolverHandler())

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}

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
