// Zip Lambdas' deployment packages (#402), stored as Lambda stores them (its COPY storage).
//
// A CloudFormation stack's zip Lambda (Code.ZipFile, or Code.S3Bucket/S3Key) is resolved at deploy by
// lambdaPackages, the CloudFormation front door's cfn.PackageStore:
//   - inline code is zipped as CloudFormation zips it (the engine names the file: index.js / index.py);
//   - an S3 object is read as the deploying caller may read it (the S3 front door's own decision,
//     s3ReadDenied), as Lambda reads a package with the caller's permissions when it creates a function.
//
// The .zip is checked (a zip archive, at most maxPackageZip, at most maxPackageUnzipped unpacked, no entry
// outside its root) and kept in platform bucket lambda-code at <namespace>/<sha256>.zip, which no account
// reaches through the S3 API (s3authz.PlatformBuckets). The Function names it by its SHA-256
// (spec.code.source.package), so a later change to the S3 object never changes the function.
//
// A function's pods fetch their package at cold start from /v1/function-code with their own identity token
// (functionCodeHandler): the shim checks the token is a pod Knative runs for that function — the check that
// gives a function its execution role (functionOf) — and serves that function's package and no other. The
// handler already holds that token (it is how its role's credentials are fetched), so it learns nothing new:
// it can fetch the code it already runs.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/minio/minio-go/v7"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

const (
	// lambdaCodeBucket is the platform bucket deployment packages are kept in (s3authz.PlatformBuckets).
	lambdaCodeBucket = "lambda-code"
	// functionCodePath is where a function's pods fetch their package.
	functionCodePath = "/v1/function-code"
	// maxPackageZip is the largest package kept: the runtime refuses a larger download.
	maxPackageZip = 64 << 20
	// maxPackageUnzipped is Lambda's limit for a package unpacked (250 MB).
	maxPackageUnzipped = 250 << 20
)

// packageStore keeps deployment packages in the lambda-code bucket.
type packageStore struct {
	mc     *minio.Client
	logger *slog.Logger
}

// put stores a checked .zip for namespace's functions and returns its SHA-256 and size. Content-addressed:
// storing the same bytes again is a no-op.
func (s *packageStore) put(ctx context.Context, namespace string, body []byte) (cfn.StoredPackage, error) {
	if err := checkPackage(body); err != nil {
		return cfn.StoredPackage{}, err
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	key := packageKey(namespace, sha)
	if ok, err := s.mc.BucketExists(ctx, lambdaCodeBucket); err != nil {
		return cfn.StoredPackage{}, fmt.Errorf("the deployment package store is unavailable: %v", err)
	} else if !ok {
		if err := s.mc.MakeBucket(ctx, lambdaCodeBucket, minio.MakeBucketOptions{}); err != nil {
			if exists, e2 := s.mc.BucketExists(ctx, lambdaCodeBucket); e2 != nil || !exists {
				return cfn.StoredPackage{}, fmt.Errorf("the deployment package store is unavailable: %v", err)
			}
		}
	}
	if _, err := s.mc.StatObject(ctx, lambdaCodeBucket, key, minio.StatObjectOptions{}); err == nil {
		return cfn.StoredPackage{SHA256: sha, Size: int64(len(body))}, nil
	}
	if _, err := s.mc.PutObject(ctx, lambdaCodeBucket, key, bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: "application/zip"}); err != nil {
		return cfn.StoredPackage{}, fmt.Errorf("storing the deployment package: %v", err)
	}
	return cfn.StoredPackage{SHA256: sha, Size: int64(len(body))}, nil
}

func packageKey(namespace, sha string) string { return namespace + "/" + sha + ".zip" }

// outsideRoot reports whether a zip entry name would land outside the directory it is unpacked into.
func outsideRoot(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return true
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// checkPackage refuses what Lambda would not run: not a zip, too large zipped or unpacked, or an entry
// that would land outside the function's directory.
func checkPackage(body []byte) error {
	if len(body) > maxPackageZip {
		return fmt.Errorf("the deployment package is %d bytes; the largest open-infra runs is %d bytes zipped", len(body), maxPackageZip)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("the deployment package is not a .zip file: %v", err)
	}
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
		if outsideRoot(f.Name) {
			return fmt.Errorf("the deployment package has an entry outside its root: %q", f.Name)
		}
	}
	if total > maxPackageUnzipped {
		return fmt.Errorf("unzipped size must be smaller than %d bytes (the deployment package is %d bytes unzipped)", uint64(maxPackageUnzipped), total)
	}
	return nil
}

// zipInline is inline code as a .zip, the same bytes for the same files (a fixed modification time, files
// in name order), so a stack update with unchanged code stores nothing new and changes nothing.
func zipInline(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		hdr := &zip.FileHeader{Name: n, Method: zip.Deflate, Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)}
		hdr.SetMode(0o644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(w, files[n]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// lambdaPackages is the CloudFormation front door's cfn.PackageStore for one request: an S3 package is
// read as that request's caller (withRequest).
type lambdaPackages struct {
	h     *cfnDoorway
	req   *http.Request
	store *packageStore
}

func (p *lambdaPackages) Store(ctx context.Context, namespace string, pkg *cfn.CodePackage) (cfn.StoredPackage, error) {
	var body []byte
	var err error
	if pkg.Inline != nil {
		body, err = zipInline(pkg.Inline)
	} else {
		body, err = p.readS3(ctx, pkg)
	}
	if err != nil {
		return cfn.StoredPackage{}, err
	}
	return p.store.put(ctx, namespace, body)
}

// readS3 reads an S3 deployment package as the caller may read it, with Lambda's messages for a refusal.
func (p *lambdaPackages) readS3(ctx context.Context, pkg *cfn.CodePackage) ([]byte, error) {
	claims, ok := callerClaimsOf(p.req)
	if !ok {
		return nil, errors.New("reading the deployment package: no caller identity")
	}
	r := withCallerClaims(p.req.Clone(ctx), claims)
	if denied, _ := p.h.s3ReadDenied(r, claims, pkg.S3Bucket, pkg.S3Key); denied {
		return nil, cfn.Unauthorized(fmt.Sprintf("Your access has been denied by S3, please make sure your request credentials have permission to GetObject for %s/%s. S3 Error Code: AccessDenied. S3 Error Message: Access Denied", pkg.S3Bucket, pkg.S3Key))
	}
	obj, err := p.store.mc.GetObject(ctx, pkg.S3Bucket, pkg.S3Key, minio.GetObjectOptions{VersionID: pkg.S3Version})
	if err != nil {
		return nil, s3PackageErr(pkg, err)
	}
	defer obj.Close()
	b, err := io.ReadAll(io.LimitReader(obj, maxPackageZip+1))
	if err != nil {
		return nil, s3PackageErr(pkg, err)
	}
	return b, nil
}

func s3PackageErr(pkg *cfn.CodePackage, err error) error {
	code := minioErrToS3(err)
	msg := minio.ToErrorResponse(err).Message
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("Error occurred while GetObject. S3 Error Code: %s. S3 Error Message: %s (s3://%s/%s)", code, msg, pkg.S3Bucket, pkg.S3Key)
}

// functionCodeHandler serves a function's pods their stored deployment package.
type functionCodeHandler struct {
	identities functionIdentities
	dyn        dynamic.Interface
	store      *packageStore
	logger     *slog.Logger
}

func (h *functionCodeHandler) serve(w http.ResponseWriter, r *http.Request, requestID string) {
	if refuseIfProxied(w, r) { // in-cluster only, as the VM endpoints
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer "))
	if token == "" {
		http.Error(w, "missing function identity token", http.StatusUnauthorized)
		return
	}
	fn, ok := h.identities.functionOf(r.Context(), token)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if fn.suspended {
		http.Error(w, "the function's account is suspended", http.StatusForbidden)
		return
	}
	claim, err := h.dyn.Resource(functionClaimGVR).Namespace(fn.namespace).Get(r.Context(), fn.name, metav1.GetOptions{})
	if err != nil {
		http.Error(w, "the function could not be read; retry", http.StatusServiceUnavailable)
		return
	}
	sha, _, _ := unstructured.NestedString(claim.Object, "spec", "code", "source", "package", "sha256")
	if len(sha) != 64 {
		http.Error(w, "the function has no stored deployment package", http.StatusNotFound)
		return
	}
	obj, err := h.store.mc.GetObject(r.Context(), lambdaCodeBucket, packageKey(fn.namespace, sha), minio.GetObjectOptions{})
	if err == nil {
		var st minio.ObjectInfo
		if st, err = obj.Stat(); err == nil {
			defer obj.Close()
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Length", fmt.Sprint(st.Size))
			w.Header().Set("X-Openinfra-Code-Sha256", sha)
			w.WriteHeader(http.StatusOK)
			if _, cerr := io.Copy(w, obj); cerr != nil && h.logger != nil {
				h.logger.Warn("function-code: sending the package failed", "function", fn.namespace+"/"+fn.name, "error", cerr.Error())
			}
			return
		}
		obj.Close()
	}
	if minioErrToS3(err) == "NoSuchKey" {
		http.Error(w, "the function's deployment package is not in the store", http.StatusNotFound)
		return
	}
	if h.logger != nil {
		h.logger.Warn("function-code: reading the package failed", "function", fn.namespace+"/"+fn.name, "error", err.Error())
	}
	http.Error(w, "the deployment package store is unavailable; retry", http.StatusServiceUnavailable)
}
