// Command manager runs the opnsense-operator controller: it watches
// annotated Services and programs OPNsense HAProxy (plus optional Unbound DNS
// and ACME) over the OPNsense REST API.
package main

import (
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/trickyearlobe/opnsense-operator/internal/config"
	"github.com/trickyearlobe/opnsense-operator/internal/controller"
	"github.com/trickyearlobe/opnsense-operator/internal/provider"
	"github.com/trickyearlobe/opnsense-operator/pkg/opnsense"
)

var scheme = runtime.NewScheme()

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("starting opnsense-operator", "version", version)

	cfg, err := config.FromEnv()
	if err != nil {
		setupLog.Error(err, "invalid configuration")
		os.Exit(1)
	}

	opnClient := opnsense.NewClient(opnsense.Options{
		BaseURL:            cfg.OPNsenseURL,
		Key:                cfg.OPNsenseKey,
		Secret:             cfg.OPNsenseSecret,
		InsecureSkipVerify: cfg.OPNsenseInsecure,
	})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: cfg.MetricsAddr},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         true,
		LeaderElectionID:       "opnsense-operator.k8s.local",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	reconfigurer := provider.NewReconfigurer(opnClient, cfg.ReconfigureDebounce)
	reconfigurer.FirewallAPI = cfg.FirewallRuleAPI

	deps := provider.Deps{
		K8s:          mgr.GetClient(),
		OPN:          opnClient,
		Cfg:          cfg,
		Reconfigurer: reconfigurer,
	}

	if err := (&controller.ServiceReconciler{
		Client:    mgr.GetClient(),
		Cfg:       cfg,
		Providers: provider.Default(deps),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Service")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager", "opnsense", cfg.OPNsenseURL)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
