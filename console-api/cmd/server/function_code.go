package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/minio/minio-go/v7"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Code-viewer bounds. A Lambda deployment package can be large (50 MiB zipped,
// 250 MiB unzipped); the console preview is not a download, so we cap what we
// pull + decompress to protect the BFF's memory and guard against a zip bomb.
const (
	maxCodeZipBytes     = 25 << 20  // refuse to preview a package larger than this (zipped)
	maxCodeExtractBytes = 64 << 20  // total uncompressed budget across all files (zip-bomb guard)
	maxCodeFiles        = 1000      // cap the number of entries we enumerate
	maxCodeFileDisplay  = 512 << 10 // per-file content we return inline (larger => metadata only)
)

// codeFile is one source file in a function's package.
type codeFile struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Content   string `json:"content,omitempty"`   // UTF-8 text; empty when binary or too large
	Binary    bool   `json:"binary,omitempty"`    // not text — no inline content
	TooLarge  bool   `json:"tooLarge,omitempty"`  // exceeds the per-file display cap
	Truncated bool   `json:"truncated,omitempty"` // content was cut at the display cap
}

// codeResp is the function's source as the Code tab renders it. Mirrors the AWS
// Lambda "Code source" panel: inline files for small handlers, the unpacked zip
// for a deployment package, or an honest "not available" for a BYO container.
type codeResp struct {
	Mode        string     `json:"mode"` // "inline" | "zip" | "image" | "none"
	Runtime     string     `json:"runtime,omitempty"`
	Handler     string     `json:"handler,omitempty"`
	Image       string     `json:"image,omitempty"`  // mode=image
	Bucket      string     `json:"bucket,omitempty"` // mode=zip
	Key         string     `json:"key,omitempty"`    // mode=zip
	Files       []codeFile `json:"files"`
	TotalFiles  int        `json:"totalFiles"`
	PackageSize int64      `json:"packageSize,omitempty"` // zipped size (zip) or sum of inline files
	Note        string     `json:"note,omitempty"`        // why source isn't shown, or a truncation notice
}

// functionSpec is the slice of a kind: Function CR the code viewer needs.
type functionSpec struct {
	Spec struct {
		Image string `json:"image"`
		Code  *struct {
			Runtime string `json:"runtime"`
			Handler string `json:"handler"`
			Source  struct {
				ConfigMap string `json:"configMap"`
				Bucket    string `json:"bucket"`
				Key       string `json:"key"`
			} `json:"source"`
		} `json:"code"`
	} `json:"spec"`
}

// getFunctionCR reads a kind: Function CR via the API server (AbsPath), tolerating
// the typed-nil REST client the fake clientset hands back (see authStore.rawREST).
func getFunctionCR(ctx context.Context, cs kubernetes.Interface, ns, name string) (functionSpec, error) {
	var fn functionSpec
	rc := cs.CoreV1().RESTClient()
	if rc == nil {
		return fn, errors.New("no REST client")
	}
	if v := reflect.ValueOf(rc); v.Kind() == reflect.Ptr && v.IsNil() {
		return fn, errors.New("no REST client")
	}
	raw, err := rc.Get().AbsPath("/apis/openinfra.dev/v1/namespaces/" + ns + "/functions/" + name).DoRaw(ctx)
	if err != nil {
		return fn, err
	}
	if err := json.Unmarshal(raw, &fn); err != nil {
		return fn, err
	}
	return fn, nil
}

// handleFunctionCode returns a function's source for the console's Code tab. The
// bucket/key/configMap are resolved from the CR itself (never the caller), so
// this can't be pointed at an arbitrary object or namespace. Container-image
// functions report mode=image with no source — the same honesty AWS gives a
// container Lambda ("Code editing isn't supported for images").
func handleFunctionCode(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")

		fn, err := getFunctionCR(r.Context(), cs, ns, name)
		if err != nil {
			writeError(w, http.StatusNotFound, "function not found")
			return
		}

		// BYO container image, or no handler-code block at all: no source to show.
		if fn.Spec.Code == nil {
			out := codeResp{Mode: "image", Image: fn.Spec.Image, Files: []codeFile{}}
			if fn.Spec.Image == "" {
				out.Mode = "none"
				out.Note = "This function has no inspectable source."
			} else {
				out.Note = "This is a container-image function — its source is built outside the console and isn't viewable here (same as a container-image Lambda in AWS)."
			}
			writeJSON(w, http.StatusOK, out)
			return
		}

		out := codeResp{
			Runtime: fn.Spec.Code.Runtime,
			Handler: fn.Spec.Code.Handler,
			Files:   []codeFile{},
		}
		src := fn.Spec.Code.Source

		switch {
		case src.ConfigMap != "":
			out.Mode = "inline"
			cm, err := cs.CoreV1().ConfigMaps(ns).Get(r.Context(), src.ConfigMap, metav1.GetOptions{})
			if err != nil {
				writeError(w, http.StatusNotFound, "source ConfigMap not found")
				return
			}
			for k, v := range cm.Data {
				out.Files = append(out.Files, makeCodeFile(k, []byte(v)))
				out.PackageSize += int64(len(v))
			}
			// BinaryData carries non-UTF-8 keys (rare for handler source).
			for k, v := range cm.BinaryData {
				out.Files = append(out.Files, makeCodeFile(k, v))
				out.PackageSize += int64(len(v))
			}

		case src.Bucket != "" && src.Key != "":
			out.Mode = "zip"
			out.Bucket = src.Bucket
			out.Key = src.Key
			files, note, size, err := readZipFromMinIO(r.Context(), cs, src.Bucket, src.Key, logger)
			if err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			out.Files = files
			out.Note = note
			out.PackageSize = size

		default:
			out.Mode = "none"
			out.Note = "This function's code source is not set."
		}

		out.TotalFiles = len(out.Files)
		sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
		writeJSON(w, http.StatusOK, out)
	}
}

// readZipFromMinIO fetches the deployment package and unpacks it in memory within
// the code-viewer bounds. Returns the files, an optional truncation note, or an error.
func readZipFromMinIO(ctx context.Context, cs kubernetes.Interface, bucket, key string, logger *slog.Logger) ([]codeFile, string, int64, error) {
	cl, err := minioClient(cs)
	if err != nil {
		return nil, "", 0, errors.New("object storage unavailable")
	}
	obj, err := cl.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, "", 0, errors.New("could not read the code package")
	}
	defer obj.Close()

	// Pull at most maxCodeZipBytes+1 so we can tell "too large" from "exactly at cap".
	buf, err := io.ReadAll(io.LimitReader(obj, maxCodeZipBytes+1))
	if err != nil {
		return nil, "", 0, errors.New("could not read the code package")
	}
	if int64(len(buf)) > maxCodeZipBytes {
		return nil, "", 0, errors.New("code package is too large to preview in the console (download it from the bucket instead)")
	}
	files, note, err := unpackZipBytes(buf)
	return files, note, int64(len(buf)), err
}

// unpackZipBytes decompresses a deployment package in memory within the code-viewer
// bounds (file count, per-file display cap, total-extract budget), classifying each
// entry as text/binary/too-large. Pure (no I/O) so it is unit-testable.
func unpackZipBytes(buf []byte) ([]codeFile, string, error) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, "", errors.New("code package is not a readable .zip")
	}

	files := make([]codeFile, 0, len(zr.File))
	var extracted int64
	note := ""
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if len(files) >= maxCodeFiles {
			note = "This package has more files than the console previews; showing the first " + strconv.Itoa(maxCodeFiles) + "."
			break
		}
		cf := codeFile{Path: cleanZipPath(zf.Name), Size: int64(zf.UncompressedSize64)}
		if extracted >= maxCodeExtractBytes {
			cf.TooLarge = true
			files = append(files, cf)
			continue
		}
		// Read up to the per-file display cap (+1 to detect truncation), but never
		// beyond the remaining total-extract budget.
		budget := maxCodeExtractBytes - extracted
		limit := int64(maxCodeFileDisplay) + 1
		if limit > budget {
			limit = budget
		}
		rc, err := zf.Open()
		if err != nil {
			files = append(files, cf)
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, limit))
		rc.Close()
		extracted += int64(len(data))

		switch {
		case isBinary(data):
			cf.Binary = true
		case int64(len(data)) > maxCodeFileDisplay:
			cf.Content = string(data[:maxCodeFileDisplay])
			cf.Truncated = true
		default:
			cf.Content = string(data)
		}
		files = append(files, cf)
	}
	return files, note, nil
}

// makeCodeFile classifies an inline (ConfigMap) source file.
func makeCodeFile(name string, data []byte) codeFile {
	cf := codeFile{Path: name, Size: int64(len(data))}
	switch {
	case isBinary(data):
		cf.Binary = true
	case len(data) > maxCodeFileDisplay:
		cf.Content = string(data[:maxCodeFileDisplay])
		cf.Truncated = true
	default:
		cf.Content = string(data)
	}
	return cf
}

// isBinary reports whether data looks non-textual (a NUL byte, or not valid UTF-8).
func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return true
	}
	return !utf8.Valid(head)
}

// cleanZipPath normalizes a zip entry name for display (forward slashes, no leading ./).
func cleanZipPath(name string) string {
	p := strings.ReplaceAll(name, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return path.Clean("/" + p)[1:]
}
