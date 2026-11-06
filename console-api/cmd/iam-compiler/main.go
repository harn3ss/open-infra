// iam-compiler compiles IAM policy — the one place authority is written — into what Kubernetes still
// enforces underneath (internal/iamcompile): the iam-corpus the authorization webhook decides
// account-qualified principals with, and generated RBAC for the paths where the API server's RBAC still
// decides. It is leader-elected (one writer), recompiles on an interval, and runs in one of two modes:
//
//	IAM_COMPILER_MODE=report  (default) write the report (and status.compiled) only — nothing enforces it
//	IAM_COMPILER_MODE=apply   also write the iam-corpus and reconcile the generated RBAC
//
// Apply needs RBAC write rights (platform/security/manifests/iam-compiler-apply.yaml), granted at the
// IAM cutover; report needs only reads.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iamcompile"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	mode := iamcompile.ModeReport
	if strings.EqualFold(os.Getenv("IAM_COMPILER_MODE"), string(iamcompile.ModeApply)) {
		mode = iamcompile.ModeApply
	}
	// A new principal's control-plane rights reach the webhook one pass (plus its 30 s cache) after it is
	// made; a pass that changes nothing writes nothing, so passes are cheap.
	interval := 15 * time.Second
	if d, err := time.ParseDuration(os.Getenv("IAM_COMPILER_INTERVAL")); err == nil && d >= 10*time.Second {
		interval = d
	}
	home := getenv("IAM_HOME_NAMESPACE", iamauthz.DefaultHomeNamespace)
	ns := getenv("POD_NAMESPACE", iamcompile.CorpusNamespace)

	cfg, err := restConfig()
	if err != nil {
		logger.Error("kube client config", "err", err)
		os.Exit(1)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error("clientset", "err", err)
		os.Exit(1)
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Error("dynamic client", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
		srv := &http.Server{Addr: getenv("LISTEN_ADDR", ":8080"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server", "err", err)
		}
	}()

	writer := iamcompile.Writer{CS: cs, DC: dc, Namespace: ns}
	run := func(ctx context.Context) {
		logger.Info("iam-compiler leading", "mode", mode, "interval", interval.String())
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			once(ctx, logger, dc, cs, writer, home, mode)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}

	id, _ := os.Hostname()
	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metavFor("iam-compiler", ns),
		Client:     cs.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: id},
	}
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock: lock, ReleaseOnCancel: true,
		LeaseDuration: 30 * time.Second, RenewDeadline: 20 * time.Second, RetryPeriod: 5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() { logger.Info("iam-compiler stopped leading") },
		},
	})
}

// once runs one compile. A load failure writes nothing (the last good corpus and RBAC stand).
func once(ctx context.Context, logger *slog.Logger, dc dynamic.Interface, cs kubernetes.Interface, writer iamcompile.Writer,
	home string, mode iamcompile.Mode) {
	in, err := iamcompile.LoadInput(ctx, dc, cs, home)
	if err != nil {
		logger.Error("iam-compiler: load failed; keeping the last compile", "err", err)
		return
	}
	out := iamcompile.Compile(in)
	if err := writer.Write(ctx, mode, in, out); err != nil {
		logger.Error("iam-compiler: write failed", "mode", mode, "err", err)
		return
	}
	narrowed := 0
	for _, p := range out.Principals {
		if len(p.Dropped) > 0 {
			narrowed++
		}
	}
	logger.Info("iam-compiler: compiled", "mode", mode, "principals", len(out.Principals), "grants", len(out.Corpus),
		"clusterRoles", len(out.ClusterRoles), "clusterRoleBindings", len(out.ClusterRoleBindings),
		"roleBindings", len(out.RoleBindings), "narrowed", narrowed)
}

func restConfig() (*rest.Config, error) {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return clientcmd.BuildConfigFromFlags("", kc)
	}
	return rest.InClusterConfig()
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
