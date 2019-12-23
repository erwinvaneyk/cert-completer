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

const ErrInvalidCertChain = "failed to parse certificate chain in tls.crt"

// CertCompleter parses the TLS certificate chain in a secret with an empty
// ca.tls, and updates the secret with the last (top-most) certificate in this
// chain as the ca.crt.
//
// Although this does not guarantee that ca.crt contains a root CA, it does
// guarantee that the CA present is valid for the TLS secret.
type CertCompleter struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch

func (c *CertCompleter) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	ctx := context.Background()
	log := c.Log.WithValues("secret", req.NamespacedName.String())

	// Read the Secret
	secret := &corev1.Secret{}
	err := c.Get(ctx, req.NamespacedName, secret)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Check (and update) secret
	updatedSecret, err := c.reconcileSecret(secret)
	if err != nil {
		return reconcile.Result{}, err
	}
	if updatedSecret != nil {
		// Update ca.crt with last cert in the chain
		err = c.Update(ctx, updatedSecret)
		if err != nil {
			return reconcile.Result{}, err
		}
		log.Info("Updated the ca.crt of the TLS secret.")
	}

	return reconcile.Result{}, nil
}

func (c *CertCompleter) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(c)
}

// reconcileSecret updates the secret, augmenting the ca.crt field with the top certificate in tls.crt.
//
// If the secret was updated, the updated result is returned. Otherwise, if
// the secret was not updated, the return value is nil.
func (c *CertCompleter) reconcileSecret(secret *corev1.Secret) (updated *corev1.Secret, err error) {
	log := c.Log.WithValues("secret", fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
	log.Info("Evaluating secret...")

	// Skip secrets that are not TLS
	if secret.Type != corev1.SecretTypeTLS {
		log.Info("Skipping non-TLS secret.")
		return nil, nil
	}

	// Parse TLS secret
	data := secret.Data
	if data == nil {
		log.Info("Skipping TLS secret because it has not data.")
		return nil, nil
	}
	caCrt, tlsCrt := data["ca.crt"], data["tls.crt"]

	// Skip secrets that already have a ca.crt
	if len(caCrt) != 0 {
		log.Info("Skipping TLS secret because it already has a ca.crt.")
		return nil, nil
	}

	// Skip secrets that do not have a tls.crt
	if len(tlsCrt) == 0 {
		log.Info("Skipping TLS secret because it has an empty tls.crt.")
		return nil, nil
	}

	// Parse cert chain
	certs, err := parseCertChain(tlsCrt)
	if err != nil {
		return nil, err
	}

	log.Info("TLS secret has a certificate chain; using the last certificate as the ca.crt.", "length", len(certs))
	updatedSecret := secret.DeepCopy()
	newCaCrt := []byte(certs[len(certs)-1])
	updatedSecret.Data["ca.crt"] = newCaCrt
	return updatedSecret, nil
}

// parseCertChain extracts the individual certificates from a chain.
//
// Chain should be a valid (chain of) TLS cert.
// The array of certificates is ordered bottom up (e.g. highest index is the root certificate)
func parseCertChain(chain []byte) ([]string, error) {
	if len(chain) == 0 {
		return nil, nil
	}

	var certs []string // bottom up (e.g. highest index is the root certificate)
	var currentCert strings.Builder
	for _, line := range strings.Split(string(chain), "\n") {
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
	if currentCert.Len() > 0 {
		return nil, errors.New(ErrInvalidCertChain)
	}
	return certs, nil
}
