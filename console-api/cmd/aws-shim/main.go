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
	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"github.com/harn3ss/open-infra/console-api/internal/tracing"
	_ "github.com/lib/pq" // database/sql driver for the documentdb Postgres (DynamoDB transactions)
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/dynamic"
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

	// Fine-grained data-plane authorization: a Cedar-backed checker over kind: Policy dataPlane
	// blocks, cached and refreshed from the cluster. Additive to the coarse SAR (it can only tighten),
	// fails closed. Disabled (nil-safe no-op) if the dynamic client can't be built.
	var authzChecker *dataplaneauthz.Checker
	dyn, derr := dynamic.NewForConfig(kc.Config)
	if derr != nil {
		logger.Warn("data-plane policy engine + assume-role disabled: cannot build dynamic client", "err", derr)
	} else {
		authzChecker = dataplaneauthz.New(dataplaneauthz.K8sLoader(dyn), 30*time.Second)
		logger.Info("data-plane policy engine enabled (kind: Policy dataPlane, refresh 30s)")
	}

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

	// SQS front door state (queues + messages), Postgres-backed for faithful visibility-timeout and
	// receipt-handle (stale-rejection) semantics — see sqs_store.go and polyhedron#158. Optional:
	// unset (defaults to MONGO_PG_URI when that is set) -> the SQS handler answers an honest 501.
	var sqsSt *sqsStore
	var snsSt *snsStore
	var kmsSt *kmsStore
	var secretsSt *secretsStore
	var ebSt *ebStore
	var cwlSt *cwlStore
	var ssmSt *ssmStore
	var apigwSt *apigwStore
	var cwSt *cwStore
	var kinesisSt *kinesisStore
	var cognitoSt *cognitoStore
	if sqsURI := getenv("SQS_PG_URI", getenv("MONGO_PG_URI", "")); sqsURI != "" {
		db, serr := sql.Open("postgres", sqsURI)
		if serr != nil {
			return serr
		}
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		serr = db.PingContext(sctx)
		cancel()
		if serr != nil {
			return fmt.Errorf("SQS_PG_URI set but the SQS Postgres is unreachable: %w", serr)
		}
		sqsSt = &sqsStore{db: db}
		if serr := sqsSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("SQS schema init failed: %w", serr)
		}
		// SNS shares the same Postgres (topics + subscriptions); delivery fans out into SQS queues.
		snsSt = &snsStore{db: db}
		if serr := snsSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("SNS schema init failed: %w", serr)
		}
		// KMS shares the same Postgres for its CMK METADATA only (lifecycle state, aliases); the
		// cryptographic material lives in Vault Transit (see kms.go / vault_transit.go).
		kmsSt = &kmsStore{db: db}
		if serr := kmsSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("KMS schema init failed: %w", serr)
		}
		// Secrets Manager shares the same Postgres for secret METADATA + the version/staging-label map;
		// the values themselves are stored as KMS ciphertext (never plaintext), see secrets.go.
		secretsSt = &secretsStore{db: db}
		if serr := secretsSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("Secrets Manager schema init failed: %w", serr)
		}
		// EventBridge shares the same Postgres for buses, rules, and targets; the in-process scheduler
		// reloads rules from here after a restart. Delivery rides the durable Lambda(async)/SQS paths.
		ebSt = &ebStore{db: db}
		if serr := ebSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("EventBridge schema init failed: %w", serr)
		}
		// CloudWatch Logs shares the same Postgres for log groups/streams/events; a reaper enforces
		// genuine per-group retention (see cloudwatchlogs.go).
		cwlSt = &cwlStore{db: db}
		if serr := cwlSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("CloudWatch Logs schema init failed: %w", serr)
		}
		// SSM Parameter Store shares the same Postgres for the parameter tree + versions + labels; a
		// SecureString value is stored as KMS ciphertext (never plaintext), see ssm.go.
		ssmSt = &ssmStore{db: db}
		if serr := ssmSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("SSM schema init failed: %w", serr)
		}
		// API Gateway (HTTP API v2) shares the same Postgres for apis/routes/integrations/stages/
		// authorizers; the data plane (the runtime HTTP→Lambda proxy) reads it on every invoke.
		apigwSt = &apigwStore{db: db}
		if serr := apigwSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("API Gateway schema init failed: %w", serr)
		}
		// CloudWatch metrics + alarms share the same Postgres; the in-process evaluator (started below)
		// reads datapoints from here and fires SNS alarm actions.
		cwSt = &cwStore{db: db}
		if serr := cwSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("CloudWatch schema init failed: %w", serr)
		}
		// Kinesis Data Streams share the same Postgres for streams/shards/records; a reaper enforces each
		// stream's retention window (see kinesis.go).
		kinesisSt = &kinesisStore{db: db}
		if serr := kinesisSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("Kinesis schema init failed: %w", serr)
		}
		// Cognito user pools share the same Postgres for pools/clients/users (bcrypt password hashes).
		cognitoSt = &cognitoStore{db: db}
		if serr := cognitoSt.ensureSchema(context.Background()); serr != nil {
			return fmt.Errorf("Cognito schema init failed: %w", serr)
		}
		logger.Info("connected to the SQS/SNS/KMS/SecretsManager/EventBridge/CloudWatchLogs/SSM/APIGateway/CloudWatch/Kinesis/Cognito Postgres")
	}

	// KMS crypto backend: Vault Transit, reached with the shim's OWN SA token (k8s-auth role
	// aws-shim-kms, policy scoped to kms-* keys). nil when VAULT_ADDR is unset -> KMS answers an honest 501.
	kmsTransit := newVaultTransit()
	if kmsTransit != nil {
		logger.Info("KMS crypto backend enabled (Vault Transit)", slog.String("role", kmsTransit.role))
	}

	auth := &authenticator{
		keys:    awskeys.NewStore(cs, keysNS),
		resolve: newOwnerResolver(cs, usersNS),
	}

	// sts:AssumeRole (faithful STS temporary credentials). The AES-256 key that seals/opens the
	// stateless session tokens is Vault-custodied: the shim logs into Vault with its OWN SA token
	// (k8s-auth role aws-shim-sts) and reads sts/data/signing-key — no raw key in a cluster Secret that
	// anything with `get secrets` could read (#111 §1). The same key across replicas means a token
	// minted by one shim verifies on another. STS_SIGNING_KEY (base64 AES-256) stays an explicit
	// dev/override fallback. Unset/unavailable -> AssumeRole answers InvalidAction and no session tokens
	// are accepted, so the identity surface stays exactly as before (fail closed). Requires the dynamic
	// client (to read a role's trust).
	var stsMinter *awssts.Minter
	var roleRes roleResolver
	var stsVaultManaged bool
	rolesNS := getenv("ROLES_NAMESPACE", usersNS)
	if dyn != nil {
		key, keySource, kerr := loadSTSSigningKey(context.Background(), logger)
		if kerr != nil {
			return kerr
		}
		if key != nil {
			m, merr := awssts.NewMinter(key)
			if merr != nil {
				return merr
			}
			stsMinter = m
			roleRes = &dynRoleResolver{dyn: dyn, ns: rolesNS}
			auth.sts = stsMinter
			// Per-role session revoke (polyhedron#147): the verify path consults each role's
			// revokeSessionsBefore cutoff, read off the Role claim and cached on a short TTL so a
			// revoke bites already-issued sessions within ~one TTL without a GET per request.
			auth.revoke = newRoleCutoffCache(dyn, rolesNS, roleCutoffTTL)
			stsVaultManaged = keySource == "vault"
			logger.Info("sts:AssumeRole enabled (temporary session credentials)",
				slog.String("keySource", keySource), slog.String("rolesNamespace", rolesNS))
		} else {
			logger.Info("sts:AssumeRole disabled: no sealing key in Vault (sts/signing-key) and STS_SIGNING_KEY unset")
		}
	}

	// Workload identity (sts:AssumeRoleWithWebIdentity, IRSA-shaped): a pod's projected SA token,
	// verified via a k8s TokenReview against the shim's audience. Enabled alongside AssumeRole.
	var webIDReviewer tokenReviewer
	if stsMinter != nil {
		aud := getenv("STS_WEB_IDENTITY_AUDIENCE", "sts.openinfra")
		webIDReviewer = &k8sTokenReviewer{cs: cs, audience: aud}
		logger.Info("sts:AssumeRoleWithWebIdentity enabled (workload identity)", slog.String("audience", aud))
	}

	// External OIDC identity providers (kind: IdentityProvider — #136 §2): a token from a registered
	// issuer may assume a role whose trust names "OIDC::<provider>". The registry is the spec-mirror
	// ConfigMaps the IdentityProvider composition renders into the shim namespace (label-selected,
	// short TTL); verification reuses the same go-oidc path as the AppSync JWT auth. Enabled whenever
	// AssumeRole is — it does nothing until an operator registers a provider.
	var oidcWebID oidcVerifier
	if stsMinter != nil {
		idpNS := getenv("IDENTITY_PROVIDER_NAMESPACE", "open-infra-aws-shim")
		oidcWebID = newOIDCWebIdentity(cs, idpNS, time.Minute)
		logger.Info("sts:AssumeRoleWithWebIdentity: external OIDC providers enabled", slog.String("namespace", idpNS))
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
	dynamoH.authz = authzChecker
	dynamoH.startTTLReaper(context.Background(), 60*time.Second) // no-op when the data layer is unset
	// Register declared kind: Table resources (spec-mirror ConfigMaps) into the table registry, so a
	// cfn-deployed / GitOps-applied table is usable without a runtime CreateTable. No-op when the
	// data layer is unset. TABLE_CONFIG_NAMESPACE is where the Table composition writes its mirrors.
	dynamoH.startTableSync(context.Background(), getenv("TABLE_CONFIG_NAMESPACE", "open-infra-console"), 30*time.Second)
	lambdaH := newLambdaHandler(cs, fnNS, svcSuffix, asyncInv, logger)
	lambdaH.authz = authzChecker
	region := getenv("AWS_REGION", "us-east-1")
	sqsH := newSQSHandler(cs, authzNS, account, region, sqsSt, logger)
	sqsH.authz = authzChecker
	snsH := newSNSHandler(cs, authzNS, account, region, snsSt, sqsSt, logger)
	snsH.authz = authzChecker
	kmsH := newKMSHandler(cs, authzNS, account, region, kmsTransit, kmsSt, logger)
	kmsH.authz = authzChecker
	// Secrets Manager reuses the SAME Vault Transit client as KMS (role aws-shim-kms): every secret value
	// is encrypted under the transit key kms-aws-secretsmanager, so no separate Vault policy is needed.
	secretsH := newSecretsHandler(cs, authzNS, account, region, kmsTransit, secretsSt, logger)
	secretsH.authz = authzChecker
	// EventBridge reuses the async invoker (durable Lambda target delivery) and the SQS store (SQS target
	// delivery). Its in-process scheduler is started below once the run context exists.
	ebH := newEBHandler(cs, authzNS, fnNS, account, region, ebSt, asyncInv, sqsSt, logger)
	ebH.authz = authzChecker
	// RDS provisions real PostgreSQL via CloudNativePG (the data path is Postgres by construction). The
	// shim's SA holds the CNPG-management RBAC in RDS_NAMESPACE; requires the dynamic client.
	var rdsCnpg *rdsCNPG
	if dyn != nil {
		rdsCnpg = &rdsCNPG{dyn: dyn, cs: cs, ns: getenv("RDS_NAMESPACE", "open-infra-rds")}
		logger.Info("RDS front door enabled (CloudNativePG Postgres)", slog.String("namespace", rdsCnpg.ns))
	}
	rdsH := newRDSHandler(cs, rdsCnpg, authzNS, account, region, logger)
	rdsH.authz = authzChecker
	cwlH := newCWLHandler(cs, authzNS, account, region, cwlSt, logger)
	cwlH.authz = authzChecker
	// SSM Parameter Store reuses the SAME Vault Transit client as KMS (role aws-shim-kms): SecureString
	// values are encrypted under the transit key kms-aws-ssm, so no separate Vault policy is needed.
	ssmH := newSSMHandler(cs, authzNS, account, region, kmsTransit, ssmSt, logger)
	ssmH.authz = authzChecker
	// API Gateway (HTTP API v2): control plane (apigatewayv2 mgmt) + the runtime HTTP→Lambda proxy. The
	// proxy reaches Functions the same cluster-local way lambdaH does (fnNS/svcSuffix). APIGW_INVOKE_BASE
	// is the public base for the invoke URL returned as apiEndpoint.
	apigwInvokeBase := getenv("APIGW_INVOKE_BASE", "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566")
	apigwH := newAPIGWHandler(cs, authzNS, account, region, fnNS, svcSuffix, apigwInvokeBase, apigwSt, logger)
	apigwH.authz = authzChecker
	// CloudWatch metrics + alarms (SigV4 service name "monitoring"). The alarm evaluator (started below)
	// fires SNS AlarmActions through the SNS handler.
	cwmH := newCWHandler(cs, authzNS, account, region, cwSt, snsH, logger)
	cwmH.authz = authzChecker
	// Kinesis Data Streams (ordered, sharded, replayable) — Postgres-backed; SigV4 service name "kinesis".
	kinesisH := newKinesisHandler(cs, authzNS, account, region, kinesisSt, logger)
	kinesisH.authz = authzChecker
	// IAM management (roles/policies/users/access-keys) — creates the kind: Role/Policy/User CRDs via the
	// dynamic client and translates AWS policy JSON → Cedar (polyhedron#168/#174). nil dyn → honest 5xx.
	var iamH *iamHandler
	if dyn != nil {
		iamH = newIAMHandler(cs, dyn, awskeys.NewStore(cs, keysNS), authzChecker, usersNS, account, region, logger)
	}
	// Cognito user pools: real RS256 JWT-issuing pools. The signing key is persisted in a Secret (so tokens
	// survive a restart); the pool issuer/JWKS is served by this shim so the API Gateway JWT authorizer (#169)
	// and apps can verify. nil signer/store → honest 5xx.
	var cognitoH *cognitoHandler
	if cognitoSt != nil {
		signer, serr := loadOrCreateSigner(context.Background(), cs, keysNS)
		if serr != nil {
			logger.Warn("cognito signing key unavailable; Cognito will answer 5xx", "error", serr.Error())
		} else {
			cognitoIssuerBase := getenv("COGNITO_ISSUER_BASE", apigwInvokeBase)
			cognitoH = newCognitoHandler(cs, authzNS, account, region, cognitoIssuerBase, cognitoSt, signer, logger)
			cognitoH.authz = authzChecker
		}
	}
	services := map[string]awsService{
		"s3":             &s3Handler{cs: cs, mc: mc, authzNS: authzNS, authz: authzChecker, logger: logger},
		"sts":            &stsHandler{account: account, minter: stsMinter, roles: roleRes, webID: webIDReviewer, oidcWebID: oidcWebID, logger: logger},
		"lambda":         lambdaH,
		"appsync":        newAppsyncHandler(cs, graphqlEndpoint, authzNS, logger),
		"dynamodb":       dynamoH,
		"sqs":            sqsH,
		"sns":            snsH,
		"kms":            kmsH,
		"secretsmanager": secretsH,
		"events":         ebH,
		"rds":            rdsH,
		"logs":           cwlH,
		"ssm":            ssmH,
		"apigateway":     apigwH,
		"monitoring":     cwmH,
		"kinesis":        kinesisH,
	}
	if iamH != nil {
		services["iam"] = iamH
	}
	if cognitoH != nil {
		services["cognito-idp"] = cognitoH
	}
	router := newRouter(logger, auth, jwtAuth, lambdaAuth, services)

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
	if sqsSt != nil {
		// Message retention reaper: delete messages past their queue's MessageRetentionPeriod. Exits
		// when ctx is cancelled.
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := sqsSt.reapExpired(context.Background()); err != nil {
						logger.Warn("sqs retention reaper error", "error", err.Error())
					}
				}
			}
		}()
	}
	if cwlSt != nil {
		// CloudWatch Logs retention reaper: genuinely enforce each log group's retentionInDays so the
		// value DescribeLogGroups reports is the truth, not a claim (AU-11). Exits when ctx is cancelled.
		go func() {
			t := time.NewTicker(15 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := cwlSt.reapExpired(context.Background(), time.Now()); err != nil {
						logger.Warn("cloudwatchlogs retention reaper error", "error", err.Error())
					}
				}
			}
		}()
	}
	if ebSt != nil {
		// EventBridge scheduler: fires enabled rate()/cron() rules and delivers to their targets on the
		// durable path. Rules are persisted, so it resumes after a restart. Exits when ctx is cancelled.
		go ebH.runScheduler(ctx)
	}
	if cwSt != nil {
		// CloudWatch alarm evaluator: periodically evaluates every alarm against its metric datapoints,
		// transitions OK/ALARM/INSUFFICIENT_DATA, and fires SNS AlarmActions on entry to ALARM. Alarms are
		// persisted, so it resumes after a restart. Exits when ctx is cancelled.
		cwmH.startEvaluator(ctx, time.Duration(atoiDefault(getenv("CW_ALARM_EVAL_INTERVAL_SECONDS", "20"), 20))*time.Second)
	}
	if kinesisSt != nil {
		// Kinesis retention reaper: genuinely enforce each stream's retention window so the reported
		// RetentionPeriodHours is truthful (records past the window are trimmed). Exits when ctx is cancelled.
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if _, err := kinesisSt.reap(context.Background()); err != nil {
						logger.Warn("kinesis retention reaper error", "error", err.Error())
					}
				}
			}
		}()
	}
	if kmsSt != nil && kmsTransit != nil {
		// KMS crypto-erase reaper: destroy the Vault key material of CMKs whose deletion window has
		// elapsed, then drop their metadata (the real, irreversible key-deletion guarantee). Exits when
		// ctx is cancelled.
		go func() {
			t := time.NewTicker(10 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := kmsH.reapDeleted(context.Background()); err != nil {
						logger.Warn("kms crypto-erase reaper error", "error", err.Error())
					}
				}
			}
		}()
	}
	// When the sealing key is Vault-custodied, re-fetch it periodically and rotate the Minter so an
	// operator's key rotation is picked up without a restart; the previous key is retained for one
	// overlap window so live sessions are not cut mid-rotation. Exits when ctx is cancelled.
	if stsMinter != nil && stsVaultManaged {
		go rotateSTSSigningKey(ctx, stsMinter, stsKeyRefreshInterval(), logger)
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
