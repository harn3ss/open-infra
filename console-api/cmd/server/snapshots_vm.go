package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// VM snapshots — the "final snapshot before you deprovision a VM" half of the feature. VMs are
// KubeVirt; their root disk is a Longhorn PVC when highAvailability is on (local-path otherwise,
// which has no CSI snapshot). We snapshot the root PVC with the durable longhorn-backup class
// (same mechanism as managed databases) and capture the VM's shape (os/cpu/memory/cpuModel/…)
// in annotations, so restore recreates a NEW VirtualMachine that boots from a PVC restored from
// the snapshot via the composition's existingRootClaim adopt path. v1: Longhorn-rooted VMs.

const (
	vmSnapLabel   = "openinfra.dev/vm-snapshot"
	annVMSource   = "openinfra.dev/vmsnap-source"
	annVMOS       = "openinfra.dev/vmsnap-os"
	annVMCPU      = "openinfra.dev/vmsnap-cpu"
	annVMMemory   = "openinfra.dev/vmsnap-memory"
	annVMCPUModel = "openinfra.dev/vmsnap-cpumodel"
	annVMHA       = "openinfra.dev/vmsnap-ha"
	annVMNetwork  = "openinfra.dev/vmsnap-network"
	annVMDisk     = "openinfra.dev/vmsnap-disk"
	annVMCreated  = "openinfra.dev/vmsnap-createdat"
)

type vmSnapshot struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	SourceName string `json:"sourceName"`
	OS         string `json:"os"`
	CreatedAt  string `json:"createdAt"`
	Status     string `json:"status"` // creating | ready | failed
	SizeBytes  int64  `json:"sizeBytes"`
}

// vmRootAndSpec reads the KubeVirt VM (for its root PVC) and the openinfra VirtualMachine CR
// (for the spec fields restore must reproduce).
func vmRootAndSpec(ctx context.Context, cs kubernetes.Interface, ns, name string) (rootPVC string, spec map[string]any, err error) {
	// root PVC from the KubeVirt VM's "root" volume (a persistentVolumeClaim when adopted, or a
	// dataVolume — whose name equals the PVC name — when provisioned from a template).
	raw, err := cs.CoreV1().RESTClient().Get().
		AbsPath("/apis/kubevirt.io/v1/namespaces/" + ns + "/virtualmachines/" + name).DoRaw(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("read VM: %w", err)
	}
	var kv struct {
		Spec struct {
			Template struct {
				Spec struct {
					Volumes []struct {
						Name                  string `json:"name"`
						PersistentVolumeClaim *struct {
							ClaimName string `json:"claimName"`
						} `json:"persistentVolumeClaim"`
						DataVolume *struct {
							Name string `json:"name"`
						} `json:"dataVolume"`
					} `json:"volumes"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &kv); err != nil {
		return "", nil, err
	}
	for _, v := range kv.Spec.Template.Spec.Volumes {
		if v.Name != "root" {
			continue
		}
		if v.PersistentVolumeClaim != nil {
			rootPVC = v.PersistentVolumeClaim.ClaimName
		} else if v.DataVolume != nil {
			rootPVC = v.DataVolume.Name
		}
	}
	if rootPVC == "" {
		return "", nil, fmt.Errorf("could not resolve the VM's root disk")
	}

	// spec fields from the openinfra VirtualMachine CR.
	raw2, err := cs.CoreV1().RESTClient().Get().
		AbsPath("/apis/openinfra.dev/v1/namespaces/" + ns + "/virtualmachines/" + name).DoRaw(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("read openinfra VM: %w", err)
	}
	var oi struct {
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(raw2, &oi); err != nil {
		return "", nil, err
	}
	return rootPVC, oi.Spec, nil
}

// pvcStorageClass returns a PVC's storage class ("" if not found).
func pvcStorageClass(ctx context.Context, cs kubernetes.Interface, ns, name string) string {
	p, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	if p.Spec.StorageClassName != nil {
		return *p.Spec.StorageClassName
	}
	return ""
}

func str(spec map[string]any, key string) string {
	if v, ok := spec[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// POST /api/vms/{namespace}/{name}/snapshot
func handleVMSnapshotCreate(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		ctx := r.Context()
		rootPVC, spec, err := vmRootAndSpec(ctx, cs, ns, name)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if sc := pvcStorageClass(ctx, cs, ns, rootPVC); !strings.Contains(sc, "longhorn") {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "VM snapshots require a Longhorn root disk (this VM's is " + sc + "); enable highAvailability first"})
			return
		}
		id := fmt.Sprintf("vmsnap-%s-%d", name, time.Now().Unix())
		vs := map[string]any{
			"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
			"metadata": map[string]any{
				"name": id, "namespace": ns,
				"labels": map[string]string{vmSnapLabel: "true"},
				"annotations": map[string]string{
					annVMSource:   name,
					annVMOS:       str(spec, "os"),
					annVMCPU:      str(spec, "cpu"),
					annVMMemory:   str(spec, "memory"),
					annVMCPUModel: str(spec, "cpuModel"),
					annVMHA:       str(spec, "highAvailability"),
					annVMNetwork:  str(spec, "network"),
					annVMDisk:     str(spec, "diskSize"),
					annVMCreated:  time.Now().UTC().Format(time.RFC3339),
				},
			},
			"spec": map[string]any{
				"volumeSnapshotClassName": csiSnapClass,
				"source":                  map[string]any{"persistentVolumeClaimName": rootPVC},
			},
		}
		body, _ := json.Marshal(vs)
		if err := cs.CoreV1().RESTClient().Post().
			AbsPath(vsAbsPath(ns)).Body(body).SetHeader("Content-Type", "application/json").Do(ctx).Error(); err != nil {
			logger.Error("vmsnapshot: create", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create VM snapshot: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, vmSnapshot{ID: id, Namespace: ns, SourceName: name,
			OS: str(spec, "os"), CreatedAt: time.Now().UTC().Format(time.RFC3339), Status: "creating"})
	}
}

// GET /api/vm-snapshots
func handleVMSnapshotList(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawList, err := cs.CoreV1().RESTClient().Get().
			AbsPath(vsAbsPath("")).Param("labelSelector", vmSnapLabel+"=true").DoRaw(ctx)
		if err != nil {
			writeJSON(w, http.StatusOK, []vmSnapshot{})
			return
		}
		var list struct {
			Items []volumeSnapshot `json:"items"`
		}
		_ = json.Unmarshal(rawList, &list)
		out := make([]vmSnapshot, 0, len(list.Items))
		for _, vs := range list.Items {
			a := vs.Metadata.Annotations
			s := vmSnapshot{ID: vs.Metadata.Name, Namespace: vs.Metadata.Namespace,
				SourceName: a[annVMSource], OS: a[annVMOS], CreatedAt: a[annVMCreated], Status: "creating"}
			if vs.Status != nil {
				if vs.Status.Error != nil && vs.Status.Error.Message != "" {
					s.Status = "failed"
				} else if vs.Status.ReadyToUse != nil && *vs.Status.ReadyToUse {
					s.Status = "ready"
				}
				s.SizeBytes = parseQuantityBytes(vs.Status.RestoreSize)
			}
			out = append(out, s)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
		writeJSON(w, http.StatusOK, out)
	}
}

// DELETE /api/vm-snapshots?namespace=&id=
func handleVMSnapshotDelete(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, id := r.URL.Query().Get("namespace"), r.URL.Query().Get("id")
		if ns == "" || id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "namespace, id required"})
			return
		}
		if err := csiDeleteSnapshot(r.Context(), cs, ns, id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete VM snapshot: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// POST /api/vm-snapshots/restore  {id, namespace, target}
// Restores into a NEW VirtualMachine: pre-seed <target>-root from the snapshot, then create an
// openinfra VirtualMachine that adopts it (existingRootClaim). Starts Halted so the user boots it.
func handleVMSnapshotRestore(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID, Namespace, Target string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.ID == "" || in.Target == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id, namespace, target required"})
			return
		}
		ctx := r.Context()
		raw, err := cs.CoreV1().RESTClient().Get().AbsPath(vsAbsPath(in.Namespace) + "/" + in.ID).DoRaw(ctx)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "VM snapshot not found"})
			return
		}
		var vs volumeSnapshot
		_ = json.Unmarshal(raw, &vs)
		a := vs.Metadata.Annotations
		if a[vmSnapLabel] == "" && vs.Metadata.Labels[vmSnapLabel] != "true" {
			// tolerate: proceed if annotations look like a VM snapshot
		}
		size := "40Gi"
		if vs.Status != nil && vs.Status.RestoreSize != "" {
			size = vs.Status.RestoreSize
		}
		rootPVCName := in.Target + "-root"

		// 1) pre-seed the restored root PVC from the snapshot.
		ha := a[annVMHA] == "true"
		access := "ReadWriteOnce"
		scName := "longhorn"
		pvcSpec := map[string]any{
			"storageClassName": scName,
			"accessModes":      []string{access},
			"dataSource":       map[string]any{"name": in.ID, "kind": "VolumeSnapshot", "apiGroup": "snapshot.storage.k8s.io"},
			"resources":        map[string]any{"requests": map[string]any{"storage": size}},
		}
		if ha {
			// HA VM root disks are RWX Block on longhorn-migratable (needed for live migration).
			pvcSpec["storageClassName"] = "longhorn-migratable"
			pvcSpec["accessModes"] = []string{"ReadWriteMany"}
			pvcSpec["volumeMode"] = "Block"
		}
		pvc := map[string]any{
			"apiVersion": "v1", "kind": "PersistentVolumeClaim",
			"metadata": map[string]any{"name": rootPVCName, "namespace": in.Namespace},
			"spec":     pvcSpec,
		}
		pb, _ := json.Marshal(pvc)
		if err := cs.CoreV1().RESTClient().Post().
			AbsPath("/api/v1/namespaces/" + in.Namespace + "/persistentvolumeclaims").
			Body(pb).SetHeader("Content-Type", "application/json").Do(ctx).Error(); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create restore PVC: " + err.Error()})
			return
		}

		// 2) create a VirtualMachine that adopts the restored root disk (Halted).
		vmSpec := map[string]any{
			"os":                a[annVMOS],
			"existingRootClaim": rootPVCName,
			"highAvailability":  ha,
			"running":           false,
		}
		if v := a[annVMCPU]; v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				vmSpec["cpu"] = n
			}
		}
		if v := a[annVMMemory]; v != "" {
			vmSpec["memory"] = v
		}
		if v := a[annVMCPUModel]; v != "" {
			vmSpec["cpuModel"] = v
		}
		if v := a[annVMNetwork]; v != "" {
			vmSpec["network"] = v
		}
		if v := a[annVMDisk]; v != "" {
			vmSpec["diskSize"] = v
		}
		vm := map[string]any{
			"apiVersion": "openinfra.dev/v1", "kind": "VirtualMachine",
			"metadata": map[string]any{"name": in.Target, "namespace": in.Namespace},
			"spec":     vmSpec,
		}
		vb, _ := json.Marshal(vm)
		if err := cs.CoreV1().RESTClient().Post().
			AbsPath("/apis/openinfra.dev/v1/namespaces/" + in.Namespace + "/virtualmachines").
			Body(vb).SetHeader("Content-Type", "application/json").Do(ctx).Error(); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create restored VM: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "restoring", "target": in.Target})
	}
}
