package main

import (
	"log/slog"
	"net/http"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Cost Explorer — open-infra's answer to AWS Cost Explorer: "what AWS would have
// charged you." We read the live cluster (node capacity, PVCs, LoadBalancers, GPUs)
// and price it against AWS public on-demand list rates, then show the monthly bill
// you're NOT paying. Purely a read-only estimate; nothing here provisions anything.
//
// Pricing basis (us-east-1 on-demand, overridable via env so you can match your
// region / negotiated rates):
//   - compute:  AWS Fargate vCPU-hr + GB-hr (the cleanest per-core/per-GB model)
//   - GPU:      a single-GPU instance-hour (g4dn.xlarge class)
//   - storage:  EBS gp3 $/GB-month
//   - LB:       ALB base $/month
// Hours/month = 730.

const hoursPerMonth = 730.0

type costPrices struct {
	VCPUHour   float64 `json:"vcpuHour"`
	GBHour     float64 `json:"gbHour"`
	GPUHour    float64 `json:"gpuHour"`
	EBSGBMonth float64 `json:"ebsGbMonth"`
	LBMonth    float64 `json:"lbMonth"`
}

func loadCostPrices() costPrices {
	return costPrices{
		VCPUHour:   getenvFloat("COST_VCPU_HOUR", 0.04048),  // Fargate vCPU-hour
		GBHour:     getenvFloat("COST_GB_HOUR", 0.004445),   // Fargate GB-hour
		GPUHour:    getenvFloat("COST_GPU_HOUR", 0.526),     // g4dn.xlarge (1x T4) on-demand
		EBSGBMonth: getenvFloat("COST_EBS_GB_MONTH", 0.08),  // gp3
		LBMonth:    getenvFloat("COST_LB_MONTH", 16.43),     // ALB base (~$0.0225/hr)
	}
}

type costCategory struct {
	Category string  `json:"category"`
	Monthly  float64 `json:"monthly"`
	Detail   string  `json:"detail"`
}

type costByNamespace struct {
	Namespace string  `json:"namespace"`
	VCPU      float64 `json:"vcpu"`
	MemoryGiB float64 `json:"memoryGiB"`
	Monthly   float64 `json:"monthly"`
}

type costResponse struct {
	Currency    string            `json:"currency"`
	YouPay      float64           `json:"youPay"`
	MonthlyAWS  float64           `json:"monthlyAWS"`
	YearlyAWS   float64           `json:"yearlyAWS"`
	Categories  []costCategory    `json:"categories"`
	ByNamespace []costByNamespace `json:"byNamespace"`
	Totals      struct {
		Nodes         int     `json:"nodes"`
		VCPU          float64 `json:"vcpu"`
		MemoryGiB     float64 `json:"memoryGiB"`
		GPU           int     `json:"gpu"`
		StorageGiB    float64 `json:"storageGiB"`
		LoadBalancers int     `json:"loadBalancers"`
	} `json:"totals"`
	Prices costPrices `json:"prices"`
}

const gpuResource = corev1.ResourceName("nvidia.com/gpu")

func handleCost(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		p := loadCostPrices()
		var resp costResponse
		resp.Currency = "USD"
		resp.Prices = p

		// Compute + GPU: price the node fleet's allocatable capacity — "what renting
		// these boxes as EC2 would cost" (independent of whether workloads set requests).
		nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Error("cost: list nodes", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list nodes"})
			return
		}
		var vcpu, memGiB float64
		var gpu int
		for _, n := range nodes.Items {
			alloc := n.Status.Allocatable
			vcpu += float64(alloc.Cpu().MilliValue()) / 1000.0
			memGiB += float64(alloc.Memory().Value()) / (1024 * 1024 * 1024)
			if g, ok := alloc[gpuResource]; ok {
				gpu += int(g.Value())
			}
		}
		resp.Totals.Nodes = len(nodes.Items)
		resp.Totals.VCPU = round2(vcpu)
		resp.Totals.MemoryGiB = round2(memGiB)
		resp.Totals.GPU = gpu

		compute := (vcpu*p.VCPUHour + memGiB*p.GBHour) * hoursPerMonth
		gpuCost := float64(gpu) * p.GPUHour * hoursPerMonth

		// Block storage: sum PVC requested capacity (EBS-equivalent).
		var storageGiB float64
		if pvcs, err := cs.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{}); err == nil {
			for _, pvc := range pvcs.Items {
				if q, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
					storageGiB += float64(q.Value()) / (1024 * 1024 * 1024)
				}
			}
		}
		resp.Totals.StorageGiB = round2(storageGiB)
		ebs := storageGiB * p.EBSGBMonth

		// Load balancers: Services of type LoadBalancer (ALB-equivalent).
		lbCount := 0
		if svcs, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{}); err == nil {
			for _, s := range svcs.Items {
				if s.Spec.Type == corev1.ServiceTypeLoadBalancer {
					lbCount++
				}
			}
		}
		resp.Totals.LoadBalancers = lbCount
		lb := float64(lbCount) * p.LBMonth

		resp.Categories = []costCategory{
			{Category: "Compute (EC2/Fargate)", Monthly: round2(compute), Detail: f2s(round2(vcpu)) + " vCPU · " + f2s(round2(memGiB)) + " GiB"},
			{Category: "GPU (EC2 accelerated)", Monthly: round2(gpuCost), Detail: strconv.Itoa(gpu) + " GPU"},
			{Category: "Block storage (EBS)", Monthly: round2(ebs), Detail: f2s(round2(storageGiB)) + " GiB"},
			{Category: "Load balancers (ALB)", Monthly: round2(lb), Detail: strconv.Itoa(lbCount) + " LB"},
		}
		resp.MonthlyAWS = round2(compute + gpuCost + ebs + lb)
		resp.YearlyAWS = round2(resp.MonthlyAWS * 12)
		resp.YouPay = 0

		// Per-namespace breakdown from running pod requests (where the compute goes).
		ns := map[string]*costByNamespace{}
		if pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{}); err == nil {
			for _, pod := range pods.Items {
				if pod.Status.Phase != corev1.PodRunning {
					continue
				}
				e := ns[pod.Namespace]
				if e == nil {
					e = &costByNamespace{Namespace: pod.Namespace}
					ns[pod.Namespace] = e
				}
				for _, c := range pod.Spec.Containers {
					e.VCPU += float64(c.Resources.Requests.Cpu().MilliValue()) / 1000.0
					e.MemoryGiB += float64(c.Resources.Requests.Memory().Value()) / (1024 * 1024 * 1024)
				}
			}
		}
		out := make([]costByNamespace, 0, len(ns))
		for _, e := range ns {
			e.Monthly = round2((e.VCPU*p.VCPUHour + e.MemoryGiB*p.GBHour) * hoursPerMonth)
			e.VCPU = round2(e.VCPU)
			e.MemoryGiB = round2(e.MemoryGiB)
			out = append(out, *e)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Monthly > out[j].Monthly })
		resp.ByNamespace = out

		writeJSON(w, http.StatusOK, resp)
	}
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
func f2s(f float64) string      { return strconv.FormatFloat(f, 'f', -1, 64) }

func getenvFloat(key string, def float64) float64 {
	if v := getenv(key, ""); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
