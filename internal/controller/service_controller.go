// Package controller implements the reconciliation core: it resolves an
// annotated Service, manages a cleanup finalizer, and fans the work out to the
// registered providers (HAProxy, DNS, ACME, …). All OPNsense-specific logic
// lives behind the provider seam in internal/provider.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/trickyearlobe/opnsense-operator/internal/annotations"
	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/internal/provider"
)

// finalizer ensures we get a chance to remove firewall objects before the
// Service disappears from the API. It shares the operator's annotation group.
const finalizer = annotations.Finalizer

// ServiceReconciler reconciles annotated Services into OPNsense state by
// delegating to a set of providers.
type ServiceReconciler struct {
	client.Client
	Cfg       *config.Config
	Providers []provider.Provider
}

// Reconcile is the controller-runtime entrypoint.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	managed := annotations.IsExposed(&svc)
	beingDeleted := !svc.DeletionTimestamp.IsZero()

	// Deletion or opt-out: tear down via every provider, then drop the finalizer.
	if beingDeleted || !managed {
		if containsString(svc.Finalizers, finalizer) {
			if err := r.cleanup(ctx, &svc); err != nil {
				return ctrl.Result{}, fmt.Errorf("cleanup: %w", err)
			}
			if err := r.removeFinalizer(ctx, &svc); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure the finalizer is set before creating any firewall state.
	if !containsString(svc.Finalizers, finalizer) {
		if err := r.addFinalizer(ctx, &svc); err != nil {
			return ctrl.Result{}, err
		}
	}

	for _, p := range r.Providers {
		if err := p.Apply(ctx, &svc); err != nil {
			l.Error(err, "provider apply failed", "provider", p.Name(), "service", req.NamespacedName)
			return ctrl.Result{}, err
		}
	}

	// Periodic resync to heal out-of-band drift (manual GUI edits, missed events).
	return ctrl.Result{RequeueAfter: r.Cfg.ResyncPeriod}, nil
}

// cleanup runs every provider's Cleanup in reverse order, so dependents (e.g.
// the routing action) are removed before what they reference (the backend).
func (r *ServiceReconciler) cleanup(ctx context.Context, svc *corev1.Service) error {
	for i := len(r.Providers) - 1; i >= 0; i-- {
		p := r.Providers[i]
		if err := p.Cleanup(ctx, svc); err != nil {
			return fmt.Errorf("%s cleanup: %w", p.Name(), err)
		}
	}
	return nil
}

func (r *ServiceReconciler) addFinalizer(ctx context.Context, svc *corev1.Service) error {
	patch := client.MergeFrom(svc.DeepCopy())
	svc.Finalizers = append(svc.Finalizers, finalizer)
	return r.Patch(ctx, svc, patch)
}

func (r *ServiceReconciler) removeFinalizer(ctx context.Context, svc *corev1.Service) error {
	patch := client.MergeFrom(svc.DeepCopy())
	svc.Finalizers = removeString(svc.Finalizers, finalizer)
	return r.Patch(ctx, svc, patch)
}

// SetupWithManager wires the reconciler to Service events.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Named("opnsense-service").
		Complete(r)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func removeString(list []string, s string) []string {
	out := list[:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}
