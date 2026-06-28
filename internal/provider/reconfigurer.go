package provider

import (
	"context"
	"sync"
	"time"

	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Reconfigurer coalesces "apply" requests so that a burst of object mutations
// (e.g. a deployment that touches many Services at once) results in a single
// haproxy/unbound reload rather than one per change. Calling Reconfigure on
// the OPNsense API regenerates and reloads the service, which is relatively
// expensive — debouncing keeps that off the hot path.
type Reconfigurer struct {
	client   *opnsense.Client
	debounce time.Duration

	mu             sync.Mutex
	haproxyPending bool
	unboundPending bool
	timer          *time.Timer
}

// NewReconfigurer builds a Reconfigurer with the given debounce window.
func NewReconfigurer(client *opnsense.Client, debounce time.Duration) *Reconfigurer {
	return &Reconfigurer{client: client, debounce: debounce}
}

// TriggerHAProxy schedules a debounced haproxy reload.
func (r *Reconfigurer) TriggerHAProxy() { r.trigger(true, false) }

// TriggerUnbound schedules a debounced unbound reload.
func (r *Reconfigurer) TriggerUnbound() { r.trigger(false, true) }

func (r *Reconfigurer) trigger(haproxy, unbound bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.haproxyPending = r.haproxyPending || haproxy
	r.unboundPending = r.unboundPending || unbound
	if r.timer == nil {
		r.timer = time.AfterFunc(r.debounce, r.flush)
		return
	}
	r.timer.Reset(r.debounce)
}

func (r *Reconfigurer) flush() {
	r.mu.Lock()
	haproxy := r.haproxyPending
	unbound := r.unboundPending
	r.haproxyPending = false
	r.unboundPending = false
	r.mu.Unlock()

	// Use a fresh, bounded context: this fires from a timer, detached from any
	// reconcile's context.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	l := log.FromContext(ctx).WithName("reconfigurer")

	if haproxy {
		if err := r.client.HAProxy().Reconfigure(ctx); err != nil {
			l.Error(err, "haproxy reconfigure failed")
		} else {
			l.Info("haproxy reconfigured")
		}
	}
	if unbound {
		if err := r.client.Unbound().Reconfigure(ctx); err != nil {
			l.Error(err, "unbound reconfigure failed")
		} else {
			l.Info("unbound reconfigured")
		}
	}
}
