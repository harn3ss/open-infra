package accounts

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// Watch keeps d current from the cluster's namespaces: only those carrying an account label are listed
// and watched (a label selector), so an install without accounts costs one empty watch. It returns once
// the first listing is in d (or with that listing's error); the watch then runs until ctx ends, re-listing
// whenever it breaks so a change missed while disconnected is not kept. Needs list and watch on
// namespaces, which the console and the aws-shim already hold.
func Watch(ctx context.Context, cs kubernetes.Interface, d *Directory, timeout time.Duration) error {
	lctx, cancel := context.WithTimeout(ctx, timeout)
	rv, err := relist(lctx, cs, d)
	cancel()
	if err != nil {
		return fmt.Errorf("list namespaces with an account label: %w", err)
	}
	go func() {
		for ctx.Err() == nil {
			if rv == "" {
				var err error
				if rv, err = relist(ctx, cs, d); err != nil {
					rv = ""
					sleep(ctx, 5*time.Second)
					continue
				}
			}
			rv = follow(ctx, cs, d, rv)
		}
	}()
	return nil
}

// relist replaces d's view with the labeled namespaces listed now, and returns the list's resourceVersion.
func relist(ctx context.Context, cs kubernetes.Interface, d *Directory) (string, error) {
	l, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: LabelAccountID})
	if err != nil {
		return "", err
	}
	d.replace(l.Items)
	return l.ResourceVersion, nil
}

// follow applies watch events from rv until the watch ends, and returns the resourceVersion to resume from
// ("" = re-list: the watch broke in a way that may have lost events).
func follow(ctx context.Context, cs kubernetes.Interface, d *Directory, rv string) string {
	w, err := cs.CoreV1().Namespaces().Watch(ctx, metav1.ListOptions{LabelSelector: LabelAccountID, ResourceVersion: rv, AllowWatchBookmarks: true})
	if err != nil {
		sleep(ctx, 2*time.Second)
		return ""
	}
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return rv
		case ev, ok := <-w.ResultChan():
			if !ok {
				return rv // closed normally (a server timeout): resume where it stopped
			}
			ns, isNS := ev.Object.(*corev1.Namespace)
			switch ev.Type {
			case watch.Added, watch.Modified:
				if isNS {
					d.Observe(ns)
				}
			case watch.Deleted:
				if isNS {
					d.Forget(ns.Name)
				}
			case watch.Bookmark:
			case watch.Error:
				return "" // e.g. the resourceVersion expired: re-list
			}
			if isNS && ns.ResourceVersion != "" {
				rv = ns.ResourceVersion
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
