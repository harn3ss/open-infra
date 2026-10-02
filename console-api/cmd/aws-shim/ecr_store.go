// ECR doorway bookkeeping (polyhedron#177).
//
// A repository is a declaration + metadata record, not a workload: the backing OCI registry auto-creates
// a repo on first push, so the record the shim keeps is the doorway's own statement that the repo exists
// (imageTagMutability, createdAt) and what CreateRepository/DescribeRepositories/DeleteRepository report.
// Each record is a small ConfigMap in the doorway's namespace, written with the shim's OWN ServiceAccount
// (the typed clientset), labeled app.kubernetes.io/managed-by=ecr.
//
// Object-name hazard: an ECR repository name may be up to 256 chars and contain '/', '.', '_', '-' — none
// of which is a legal (or short enough) k8s object name, and two different names can sanitize to the same
// string ("my/repo", "my-repo" and "my.repo" all collapse to "my-repo"). A sanitized-name-only scheme
// would let the second create silently OVERWRITE the first. So the object name is sanitized-prefix PLUS a
// hash of the EXACT name: distinct names always get distinct objects, and the exact repositoryName is both
// stored in the data and re-verified on read, so a record can never be served under the wrong name.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ecrFieldManager = "ecr-doorway"
	ecrManagedBy    = "ecr" // app.kubernetes.io/managed-by value on every ECR doorway record
	ecrNamePrefix   = "ecr-repo-"
	ecrRepoLabel    = "ecr.openinfra.dev/repo" // listing label (the sanitized name; exact name lives in data)
)

// ecrInvalidName matches everything a k8s object-name segment may NOT contain.
var ecrInvalidName = regexp.MustCompile(`[^a-z0-9-]+`)

// ecrSanitize lowercases a repository name and collapses every illegal run to "-" (trimmed). The result
// is a label-safe/object-safe fragment but is NOT unique across repo names — repoCMName adds a hash for
// that. Capped so the final object name stays within the 63-char k8s limit.
func ecrSanitize(s string) string {
	n := strings.Trim(ecrInvalidName.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(n) > 43 { // 63 - len("ecr-repo-") - len("-<10-hex-hash>")
		n = strings.Trim(n[:43], "-")
	}
	return n
}

// repoCMName is the ConfigMap name for a repository record: the sanitized prefix plus a short hash of the
// EXACT name, so two names that sanitize alike still land on different objects (no silent overwrite).
func (h *ecrHandler) repoCMName(name string) string {
	sum := sha256.Sum256([]byte(name))
	short := hex.EncodeToString(sum[:])[:10]
	if s := ecrSanitize(name); s != "" {
		return ecrNamePrefix + s + "-" + short
	}
	return ecrNamePrefix + short
}

// ecrRepoRecord is the persisted repository metadata (the record data JSON).
type ecrRepoRecord struct {
	RepositoryName     string `json:"repositoryName"`
	ImageTagMutability string `json:"imageTagMutability"`
	CreatedAt          int64  `json:"createdAt"` // unix seconds
}

// putRepo creates or replaces a repository record. The typed clientset is used (the doorway's own SA);
// a create that races an existing object is folded into an update so the call is idempotent.
func (h *ecrHandler) putRepo(ctx context.Context, rec ecrRepoRecord) error {
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	name := h.repoCMName(rec.RepositoryName)
	data := map[string]string{"repo.json": string(blob), "repositoryName": rec.RepositoryName}
	labels := map[string]string{
		"app.kubernetes.io/managed-by": ecrManagedBy,
		ecrRepoLabel:                   ecrSanitize(rec.RepositoryName),
	}
	cms := h.cs.CoreV1().ConfigMaps(h.ns)
	existing, err := cms.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, cerr := cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.ns, Labels: labels},
			Data:       data,
		}, metav1.CreateOptions{FieldManager: ecrFieldManager})
		if apierrors.IsAlreadyExists(cerr) {
			return h.updateRepoCM(ctx, name, data, labels)
		}
		return cerr
	}
	if err != nil {
		return err
	}
	existing.Data = data
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	for k, v := range labels {
		existing.Labels[k] = v
	}
	_, err = cms.Update(ctx, existing, metav1.UpdateOptions{FieldManager: ecrFieldManager})
	return err
}

func (h *ecrHandler) updateRepoCM(ctx context.Context, name string, data, labels map[string]string) error {
	cms := h.cs.CoreV1().ConfigMaps(h.ns)
	existing, err := cms.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	existing.Data = data
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	for k, v := range labels {
		existing.Labels[k] = v
	}
	_, err = cms.Update(ctx, existing, metav1.UpdateOptions{FieldManager: ecrFieldManager})
	return err
}

// getRepo fetches a repository record by its EXACT name. The stored repositoryName is re-checked against
// the requested one (collision guard) so a hash/name coincidence can never serve the wrong record.
func (h *ecrHandler) getRepo(ctx context.Context, exactName string) (ecrRepoRecord, bool, error) {
	cm, err := h.cs.CoreV1().ConfigMaps(h.ns).Get(ctx, h.repoCMName(exactName), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ecrRepoRecord{}, false, nil
	}
	if err != nil {
		return ecrRepoRecord{}, false, err
	}
	var rec ecrRepoRecord
	if err := json.Unmarshal([]byte(cm.Data["repo.json"]), &rec); err != nil {
		return ecrRepoRecord{}, false, err
	}
	if rec.RepositoryName != exactName {
		return ecrRepoRecord{}, false, nil
	}
	return rec, true, nil
}

// listRepos returns every repository record in the doorway namespace.
func (h *ecrHandler) listRepos(ctx context.Context) ([]ecrRepoRecord, error) {
	list, err := h.cs.CoreV1().ConfigMaps(h.ns).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=" + ecrManagedBy,
	})
	if err != nil {
		return nil, err
	}
	var out []ecrRepoRecord
	for i := range list.Items {
		cm := &list.Items[i]
		if !strings.HasPrefix(cm.Name, ecrNamePrefix) {
			continue
		}
		var rec ecrRepoRecord
		if json.Unmarshal([]byte(cm.Data["repo.json"]), &rec) == nil && rec.RepositoryName != "" {
			out = append(out, rec)
		}
	}
	return out, nil
}

// deleteRepo removes a repository record (idempotent: an already-absent record is success).
func (h *ecrHandler) deleteRepo(ctx context.Context, exactName string) error {
	err := h.cs.CoreV1().ConfigMaps(h.ns).Delete(ctx, h.repoCMName(exactName), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
