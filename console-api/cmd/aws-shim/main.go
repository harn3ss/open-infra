// Command aws-shim is an AWS-SDK interception front door onto open-infra's real backends. An
// unmodified AWS SDK client, pointed at this endpoint (AWS_ENDPOINT_URL), thinks it is talking to
// AWS; the shim verifies the request's SigV4 signature against an open-infra access key, resolves
// the caller to their open-infra principal, enforces the SAME RBAC + permission boundary the
// console and Terraform provider use, calls the real backend (v1: S3 over MinIO), and re-dresses
// the response in AWS's exact byte-shape.
//
// It is NOT an emulator: it fronts durable backends, not fakes. It is opt-in and OFF by default —
// one optional AWS-shaped surface over the platform, never a core dependency. It shares the
// console-api module precisely so it reuses the one authorization core (internal/iam) rather than
// a weaker parallel auth. See docs/aws-shim.md and the design handoff.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"github.com/harn3ss/open-infra/console-api/internal/tracing"
	_ "github.com/lib/pq" // database/sql driver for the documentdb Postgres (DynamoDB transactions)
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/kubernetes"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevelFromEnv()}))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("aws-shim exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// Kubernetes client: the shim's ServiceAccount RBAC — never this process — is the authority.
	// It is used for the impersonated SubjectAccessReview, reading access-key Secrets, and
	// resolving an access key's owning kind: User.
	kc, err := k8s.New("")
	if err != nil {
		return err
	}
	cs := *kc.Clientset

	// Two DIFFERENT namespaces, deliberately split for least privilege:
	// - keysNS holds the iam-ak-<id> access-key Secrets. Default is the shim's OWN namespace, so
	// the shim's `get secrets` RBAC never reaches the console namespace (where bcrypt password
	// hashes and the session-signing key live).
	// - usersNS is where kind: User objects live (the console namespace). The shim reads USERS
	// there — never Secrets — to resolve an access key's owner to its current groups.
	keysNS := getenv("KEYS_NAMESPACE", "open-infra-aws-shim")
	usersNS := getenv("USERS_NAMESPACE", "open-infra-console")
	authzNS := getenv("AUTHZ_NAMESPACE", "default")  // namespace the coarse S3 RBAC gate checks
	fnNS := getenv("FUNCTIONS_NAMESPACE", "default") // namespace kind: Function lives in
	svcSuffix := getenv("SVC_SUFFIX", "svc.cluster.local")
	account := getenv("ACCOUNT_ID", "open-infra") // surfaced in STS ARNs
	// open-appsync engine endpoint (opt-in component `openAppsync`). Our own engine — no admin
	// secret; the shim conveys the verified principal and open-appsync enforces authz internally.
	graphqlEndpoint := getenv("GRAPHQL_ENDPOINT", "http://open-appsync.open-infra-open-appsync.svc.cluster.local:80")

	mc, err := newMinioClient()
	if err != nil {
		return err
	}

	// FerretDB (Mongo wire) backs the DynamoDB front door. Optional: if MONGO_URI is unset the
	// dynamodb handler still registers but answers an honest 501 (data layer not configured), so
	// nothing else about the shim is affected.
	var mongoDB *mongo.Database
	if uri := getenv("MONGO_URI", ""); uri != "" {
		mctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		client, cerr := mongo.Connect(mctx, options.Client().ApplyURI(uri))
		cancel()
		if cerr != nil {
			return cerr
		}
		mongoDB = client.Database(getenv("MONGO_DB", "open_infra_dynamodb"))
		logger.Info("connected to FerretDB for the DynamoDB front door", slog.String("db", mongoDB.Name()))
	}

	// The Postgres (documentdb extension) behind the SAME FerretDB, used only for atomic
	// multi-item transactions (TransactWriteItems/TransactGetItems). FerretDB has no Mongo
	// transactions, but the documentdb_api functions the mongo path also uses ARE transactional
	// under a Postgres BEGIN/COMMIT, and writes through them are read-consistent over the mongo
	// wire. Optional: unset -> Transact* answers an honest 501.
	var pg *sql.DB
	if pgURI := getenv("MONGO_PG_URI", ""); pgURI != "" {
		db, perr := sql.Open("postgres", pgURI)
		if perr != nil {
			return perr
		}
		pctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		perr = db.PingContext(pctx)
		cancel()
		if perr != nil {
			return fmt.Errorf("MONGO_PG_URI set but the documentdb Postgres is unreachable: %w", perr)
		}
		pg = db
		logger.Info("connected to the documentdb Postgres for DynamoDB transactions")
	}

	auth := &authenticator{
		keys:    awskeys.NewStore(cs, keysNS),
		resolve: newOwnerResolver(cs, usersNS),
	}

	// Optional OIDC/Cognito JWT auth for the AppSync data plane (the one non-SigV4 path). Enabled when
	// OIDC_ISSUER is set. Audience is REQUIRED (no unaudienced tokens). The mode is EXPLICIT
	// (OIDC_MODE, default aws_oidc); the issuer only picks the default groups-claim name.
	var jwtAuth *jwtAuthenticator
	if issuer := getenv("OIDC_ISSUER", ""); issuer != "" {
		audience := getenv("OIDC_AUDIENCE", "")
		if audience == "" {
			logger.Error("OIDC_ISSUER is set but OIDC_AUDIENCE is empty — refusing to enable JWT auth without audience enforcement")
			os.Exit(1)
		}
		mode := getenv("OIDC_MODE", "aws_oidc")
		if mode != "aws_oidc" && mode != "aws_cognito_user_pools" {
			logger.Error("OIDC_MODE must be aws_oidc or aws_cognito_user_pools", "got", mode)
			os.Exit(1)
		}
		groupsClaim := resolveGroupsClaim(getenv("OIDC_GROUPS_CLAIM", ""), issuer)
		discCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		ja, err := newJWTAuthenticator(discCtx, issuer, audience, groupsClaim, mode)
		cancel()
		if err != nil {
			logger.Error("OIDC init failed", "issuer", issuer, "error", err.Error())
			os.Exit(1)
		}
		jwtAuth = ja
		logger.Info("appsync OIDC/JWT auth enabled", "issuer", issuer, "mode", mode, "groupsClaim", groupsClaim)
	}

	// Optional @aws_lambda authorizer for the AppSync data plane (the fifth AWS auth mode). Enabled when
	// LAMBDA_AUTHORIZER_FUNCTION names a kind: Function the shim invokes to authorize each request. It is
	// MUTUALLY EXCLUSIVE with OIDC/JWT: both own the single non-SigV4 token path, so enabling both is a
	// misconfiguration the shim refuses to start with (the token would be ambiguous). The authorizer's
	// returned identity (resolverContext) maps into the one policy world; its deniedFields/ttlOverride are
	// deliberately NOT honored — see lambda_authorizer.go.
	var lambdaAuth *lambdaAuthorizer
	if fn := getenv("LAMBDA_AUTHORIZER_FUNCTION", ""); fn != "" {
		if jwtAuth != nil {
			logger.Error("LAMBDA_AUTHORIZER_FUNCTION and OIDC_ISSUER are both set — the shim's non-SigV4 token path is single-mode; enable only one")
			os.Exit(1)
		}
		laNS := getenv("LAMBDA_AUTHORIZER_NAMESPACE", fnNS)
		userClaim := getenv("LAMBDA_AUTHORIZER_USER_CLAIM", "sub")
		groupsClaim := getenv("LAMBDA_AUTHORIZER_GROUPS_CLAIM", "groups")
		lambdaAuth = newLambdaAuthorizer(fn, laNS, svcSuffix, userClaim, groupsClaim)
		logger.Info("appsync Lambda authorizer enabled", "function", fn, "namespace", laNS,
			"userClaim", userClaim, "groupsClaim", groupsClaim)
	}

	// Optional durable async (Event) Lambda invocation. When the shim has NATS, Event invokes are queued
	// to JetStream and a background worker delivers them (retries + dead-letter); without NATS, Event
	// invocations are refused honestly (no durable queue) while synchronous invoke still works.
	var asyncInv *asyncInvoker
	if natsURL := getenv("NATS_URL", ""); natsURL != "" {
		if ai, err := newAsyncInvoker(natsURL, fnNS, svcSuffix, 3, logger); err != nil {
			logger.Error("async Lambda (Event) invocation disabled — NATS connect failed", "error", err.Error())
		} else {
			asyncInv = ai
			logger.Info("async Lambda (Event) invocation enabled", "nats", natsURL)
		}
	}

	// Distributed tracing (#67): opt-in via OTEL_EXPORTER_OTLP_ENDPOINT (Tempo). W3C
	// traceparent propagation lets a shim request stitch through to open-appsync/etc.
	shutdownTracing, err := tracing.Init(context.Background(), "aws-shim")
	if err != nil {
		logger.Warn("tracing init failed; continuing without traces", slog.String("error", err.Error()))
	} else {
		defer func() { _ = shutdownTracing(context.Background()) }()
	}

	// The service registry: one front door, many domain experts (keyed by the AWS service name the
	// client signs for). Adding a service is one more entry. Each carries its own decoder,
	// authorization mapping, and error dialect; SigV4 authentication is shared, done once.
	dynamoH := newDynamoHandler(cs, authzNS, mongoDB, pg, getenv("MONGO_DB", "open_infra_dynamodb"), logger)
	dynamoH.startTTLReaper(context.Background(), 60*time.Second) // no-op when the data layer is unset
	router := newRouter(logger, auth, jwtAuth, lambdaAuth, map[string]awsService{
		"s3":       &s3Handler{cs: cs, mc: mc, authzNS: authzNS, logger: logger},
		"sts":      &stsHandler{account: account, logger: logger},
		"lambda":   newLambdaHandler(cs, fnNS, svcSuffix, asyncInv, logger),
		"appsync":  newAppsyncHandler(cs, graphqlEndpoint, authzNS, logger),
		"dynamodb": dynamoH,
	})

	addr := getenv("LISTEN_ADDR", ":4566")
	srv := &http.Server{
		Addr:              addr,
		Handler:           otelhttp.NewHandler(router, "aws-shim"),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("aws-shim listening", "addr", addr, "version", version,
			"minioEndpoint", getenv("MINIO_ENDPOINT", defaultMinioEndpoint),
			"keysNamespace", keysNS, "usersNamespace", usersNS)
		cert, key := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
		var lerr error
		if cert != "" && key != "" {
			lerr = srv.ListenAndServeTLS(cert, key)
		} else {
			// Plain HTTP is expected in-cluster (TLS terminated at the ingress/mesh); clients set
			// AWS_ENDPOINT_URL to the http:// service address. TLS_CERT_FILE/TLS_KEY_FILE enable
			// direct TLS for the SDK-trusts-the-cert deployment.
			lerr = srv.ListenAndServe()
		}
		if lerr != nil && !errors.Is(lerr, http.ErrServerClosed) {
			serverErr <- lerr
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if asyncInv != nil {
		go asyncInv.run(ctx) // durable async-invoke delivery worker; exits when ctx is cancelled
		defer asyncInv.Close()
	}
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

func newRouter(logger *slog.Logger, auth *authenticator, jwt *jwtAuthenticator, lambdaAuth *lambdaAuthorizer, services map[string]awsService) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	// Health is unauthenticated (kubelet probes it); it is NOT an AWS request path.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Every other request is an AWS-SDK call; the serviceRouter authenticates once and dispatches
	// to the handler for the service the client signed for.
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	logger.Info("aws services registered", "services", names)
	r.Handle("/*", &serviceRouter{auth: auth, jwt: jwt, lambdaAuth: lambdaAuth, services: services, logger: logger})
	return r
}

const defaultMinioEndpoint = "minio.minio.svc.cluster.local:9000"

// newMinioClient builds the MinIO bridge client from a scoped, NON-root service account. v1 uses a
// single scoped identity to MinIO (per-principal MinIO users are the flagged graduation step); its
// bucket scope is the MinIO policy attached to MINIO_ACCESS_KEY.
func newMinioClient() (*minio.Client, error) {
	endpoint := getenv("MINIO_ENDPOINT", defaultMinioEndpoint)
	ak, sk := os.Getenv("MINIO_ACCESS_KEY"), os.Getenv("MINIO_SECRET_KEY")
	if ak == "" || sk == "" {
		return nil, errors.New("MINIO_ACCESS_KEY / MINIO_SECRET_KEY must be set (the shim's scoped MinIO service account)")
	}
	secure := os.Getenv("MINIO_SECURE") == "true"
	return minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(ak, sk, ""),
		Secure: secure,
	})
}

// newOwnerResolver resolves an access key's owner (a kind: User name) to its CURRENT impersonation
// groups, fresh on every request, via the same iam.openinfra.dev User read the console uses and the
// single-source-of-truth iam.GroupsFromSpec transform. A missing or disabled User → ok=false.
func newOwnerResolver(cs kubernetes.Interface, ns string) ownerResolver {
	return func(ctx context.Context, owner string) ([]string, bool) {
		if owner == "" {
			return nil, false
		}
		rc := cs.CoreV1().RESTClient()
		if rc == nil {
			return nil, false
		}
		path := "/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/users/" + owner
		raw, err := rc.Get().AbsPath(path).DoRaw(ctx)
		if err != nil {
			return nil, false
		}
		var u struct {
			Spec struct {
				Groups   []string `json:"groups"`
				Disabled bool     `json:"disabled"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &u); err != nil || u.Spec.Disabled {
			return nil, false
		}
		return iam.GroupsFromSpec(u.Spec.Groups), true
	}
}

// requestIDFrom returns chi's per-request ID (echoed as x-amz-request-id), or a fresh random id.
func requestIDFrom(r *http.Request) string {
	if id := middleware.GetReqID(r.Context()); id != "" {
		return id
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func logLevelFromEnv() slog.Level {
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
