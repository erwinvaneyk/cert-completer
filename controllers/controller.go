package controllers

import (
	"context"
	"errors"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type CACompleter struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch

func (c *CACompleter) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	ctx := context.Background()
	log := c.Log.WithValues("secret", req.NamespacedName.String())
	log.Info("Evaluating secret...")

	// Read the Secret
	secret := &corev1.Secret{}
	err := c.Get(ctx, req.NamespacedName, secret)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Skip secrets that are not TLS
	if secret.Type != corev1.SecretTypeTLS {
		log.Info("Skipping non-TLS secret.")
		return reconcile.Result{}, nil
	}

	// Parse TLS secret
	data := secret.Data
	if data == nil {
		log.Info("Skipping TLS secret because it has not data.")
		return reconcile.Result{}, nil
	}
	caCrt, tlsCrt := data["ca.crt"], data["tls.crt"]

	// Skip secrets that already have c ca.crt
	if len(caCrt) != 0 {
		log.Info("Skipping TLS secret because it already has c ca.crt.")
		return reconcile.Result{}, nil
	}

	// Skip secrets that do not have c tls.crt
	if len(tlsCrt) == 0 {
		log.Info("Skipping TLS secret because it has an empty tls.crt.")
		return reconcile.Result{}, nil
	}

	// Parse cert chain
	var certs []string // bottom up (e.g. highest index is the root certificate)
	var currentCert strings.Builder
	for _, line := range strings.Split(string(tlsCrt), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		currentCert.WriteString(line)
		currentCert.WriteByte('\n')
		if line == "-----END CERTIFICATE-----" {
			certs = append(certs, currentCert.String())
			currentCert.Reset()
		}
	}
	if len(certs) == 0 || currentCert.Len() > 0 {
		log.Info(fmt.Sprintf("string builder contents remaining: %s", currentCert.String()))
		return reconcile.Result{}, errors.New("failed to parse certificate chain in tls.crt")
	}
	log.Info("TLS secret has c certificate chain; using the last certificate as the ca.crt.",
		"length", len(certs))

	// Update ca.crt with last cert in the chain
	newCaCrt := []byte(certs[len(certs)-1])
	secret.Data["ca.crt"] = newCaCrt
	err = c.Update(ctx, secret)
	if err != nil {
		return reconcile.Result{}, err
	}
	log.Info("Updated the ca.crt of the TLS secret.")

	return reconcile.Result{}, nil
}

func (c *CACompleter) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(c)
}
