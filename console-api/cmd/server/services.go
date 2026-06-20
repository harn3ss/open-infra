package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// --- MinIO ("S3") bucket browser -------------------------------------------
//
// The console reads the MinIO root credentials from the `minio` secret (the SA
// has a narrow Role granting GET on just that secret) and talks to MinIO's S3
// API in-cluster. The client is built lazily and cached on first success.

var (
	minioMu     sync.Mutex
	minioCached *minio.Client
)

func minioClient(cs kubernetes.Interface) (*minio.Client, error) {
	minioMu.Lock()
	defer minioMu.Unlock()
	if minioCached != nil {
		return minioCached, nil
	}
	ns := getenv("MINIO_SECRET_NAMESPACE", "minio")
	name := getenv("MINIO_SECRET_NAME", "minio")
	sec, err := cs.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	cl, err := minio.New(getenv("MINIO_ENDPOINT", "minio.minio.svc.cluster.local:9000"), &minio.Options{
		Creds: credentials.NewStaticV4(
			string(sec.Data["rootUser"]),
			string(sec.Data["rootPassword"]),
			"",
		),
		Secure: getenv("MINIO_SECURE", "") == "true",
	})
	if err != nil {
		return nil, err
	}
	minioCached = cl // cache only on success so a transient failure can retry
	return cl, nil
}

type bucketResp struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

func handleBuckets(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cl, err := minioClient(cs)
		if err != nil {
			logger.Error("minio client", slog.String("error", err.Error()))
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		buckets, err := cl.ListBuckets(ctx)
		if err != nil {
			logger.Error("list buckets", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "could not list buckets")
			return
		}
		out := make([]bucketResp, 0, len(buckets))
		for _, b := range buckets {
			out = append(out, bucketResp{Name: b.Name, CreatedAt: b.CreationDate})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type objectResp struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"lastModified"`
	IsPrefix     bool      `json:"isPrefix"`
}

func handleBucketObjects(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		prefix := r.URL.Query().Get("prefix")
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		out := make([]objectResp, 0, 64)
		for obj := range cl.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: false}) {
			if obj.Err != nil {
				logger.Error("list objects", slog.String("error", obj.Err.Error()))
				writeError(w, http.StatusBadGateway, "could not list objects")
				return
			}
			out = append(out, objectResp{
				Key:          obj.Key,
				Size:         obj.Size,
				LastModified: obj.LastModified,
				IsPrefix:     strings.HasSuffix(obj.Key, "/"),
			})
			if len(out) >= 1000 { // cap a single page
				break
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// --- NATS JetStream ("SQS/SNS") stream stats -------------------------------
//
// Reads the NATS monitoring endpoint (/jsz) and flattens JetStream streams with
// live counts. No client library needed — it's a plain HTTP/JSON endpoint.

type streamResp struct {
	Name      string   `json:"name"`
	Account   string   `json:"account"`
	Subjects  []string `json:"subjects"`
	Messages  uint64   `json:"messages"`
	Bytes     uint64   `json:"bytes"`
	Consumers int      `json:"consumers"`
}

func handleQueues(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := getenv("NATS_MONITOR_URL", "http://nats-headless.nats.svc.cluster.local:8222")
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/jsz?streams=true", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Error("nats jsz", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "messaging unavailable")
			return
		}
		defer resp.Body.Close()

		var jz struct {
			AccountDetails []struct {
				Name         string `json:"name"`
				StreamDetail []struct {
					Name   string `json:"name"`
					Config struct {
						Subjects []string `json:"subjects"`
					} `json:"config"`
					State struct {
						Messages      uint64 `json:"messages"`
						Bytes         uint64 `json:"bytes"`
						ConsumerCount int    `json:"consumer_count"`
					} `json:"state"`
				} `json:"stream_detail"`
			} `json:"account_details"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&jz); err != nil {
			writeError(w, http.StatusBadGateway, "could not parse JetStream status")
			return
		}
		out := make([]streamResp, 0)
		for _, a := range jz.AccountDetails {
			for _, s := range a.StreamDetail {
				out = append(out, streamResp{
					Name:      s.Name,
					Account:   a.Name,
					Subjects:  s.Config.Subjects,
					Messages:  s.State.Messages,
					Bytes:     s.State.Bytes,
					Consumers: s.State.ConsumerCount,
				})
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// --- MinIO bucket + object writes -------------------------------------------

func handleCreateBucket(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			writeError(w, http.StatusBadRequest, "bucket name required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := cl.MakeBucket(ctx, body.Name, minio.MakeBucketOptions{}); err != nil {
			logger.Error("make bucket", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"name": body.Name})
	}
}

func handleDeleteBucket(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := cl.RemoveBucket(ctx, chi.URLParam(r, "bucket")); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleUploadObject(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		key := r.URL.Query().Get("key")
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		if _, err := cl.PutObject(r.Context(), bucket, key, r.Body, r.ContentLength,
			minio.PutObjectOptions{ContentType: ct}); err != nil {
			logger.Error("put object", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"key": key})
	}
}

func handleDownloadObject(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		key := r.URL.Query().Get("key")
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		obj, err := cl.GetObject(r.Context(), bucket, key, minio.GetObjectOptions{})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		defer obj.Close()
		st, err := obj.Stat()
		if err != nil {
			writeError(w, http.StatusNotFound, "object not found")
			return
		}
		if st.ContentType != "" {
			w.Header().Set("Content-Type", st.ContentType)
		}
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size, 10))
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(key)))
		_, _ = io.Copy(w, obj)
	}
}

func handleDeleteObject(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bucket := chi.URLParam(r, "bucket")
		key := r.URL.Query().Get("key")
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required")
			return
		}
		cl, err := minioClient(cs)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "object storage unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := cl.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{}); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Model chat proxy (the "playground") ------------------------------------
//
// Reads the <name>-model secret (OPENAI_BASE_URL + OPENAI_API_KEY) and forwards
// the request to the model's in-cluster OpenAI-compatible endpoint with the key,
// so the browser can chat with a Model without ever seeing the key.

func handleModelChat(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		sec, err := cs.CoreV1().Secrets(ns).Get(r.Context(), name+"-model", metav1.GetOptions{})
		if err != nil {
			writeError(w, http.StatusBadGateway, "model connection secret not found")
			return
		}
		base := string(sec.Data["OPENAI_BASE_URL"])
		key := string(sec.Data["OPENAI_API_KEY"])
		if base == "" {
			writeError(w, http.StatusBadGateway, "model endpoint unknown")
			return
		}
		// Inject the model tag from the secret so callers needn't know it (the
		// OpenAI API requires a "model" field).
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			payload = map[string]any{}
		}
		if _, ok := payload["model"]; !ok {
			if m := string(sec.Data["MODEL"]); m != "" {
				payload["model"] = m
			}
		}
		buf, _ := json.Marshal(payload)
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(base, "/")+"/chat/completions", bytes.NewReader(buf))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "bad request")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Error("model chat", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "model unreachable")
			return
		}
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}
