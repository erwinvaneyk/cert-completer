package controllers

import (
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"strings"
	"testing"
)

// It should reconcile valid TLS secrets.
func TestCACompleter_reconcileSecret_certChain(t *testing.T) {
	ctrl := CACompleter{
		Log: zap.New(),
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-secret",
			Namespace: "test-namespace",
		},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{
				"ca.crt": nil,
				"tls.crt": []byte(strings.Join(certs, "")),
		},
	}

	updatedSecret, err := ctrl.reconcileSecret(secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, updatedSecret)
	assert.Equal(t, certs[len(certs)-1], string(updatedSecret.Data["ca.crt"]))
	assert.Equal(t, updatedSecret.Data["tls.crt"], updatedSecret.Data["tls.crt"])
}

// It should reconcile valid TLS secrets with just one certificate in the chain.
func TestCACompleter_reconcileSecret_singleCert(t *testing.T) {
	ctrl := CACompleter{
		Log: zap.New(),
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-secret",
			Namespace: "test-namespace",
		},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{
			"ca.crt": nil,
			"tls.crt": []byte(certs[0]),
		},
	}

	updatedSecret, err := ctrl.reconcileSecret(secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, updatedSecret)
	assert.Equal(t, certs[0], string(updatedSecret.Data["ca.crt"]))
	assert.Equal(t, updatedSecret.Data["tls.crt"], updatedSecret.Data["tls.crt"])
}

// It should ignore non-TLS secrets.
func TestCACompleter_reconcileSecret_nonTLS(t *testing.T) {
	ctrl := CACompleter{
		Log: zap.New(),
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-secret",
			Namespace: "test-namespace",
		},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{
			"ca.crt": nil,
			"tls.crt": []byte(strings.Join(certs, "")),
		},
	}

	updatedSecret, err := ctrl.reconcileSecret(secret)
	assert.NoError(t, err)
	assert.Empty(t, updatedSecret)
}

// It should ignore complete TLS secrets (that already have a CA).
func TestCACompleter_reconcileSecret_completeSecret(t *testing.T) {
	ctrl := CACompleter{
		Log: zap.New(),
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-secret",
			Namespace: "test-namespace",
		},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{
			"ca.crt": []byte(certs[len(certs) - 1]),
			"tls.crt": []byte(strings.Join(certs, "")),
		},
	}

	updatedSecret, err := ctrl.reconcileSecret(secret)
	assert.NoError(t, err)
	assert.Empty(t, updatedSecret)
}


// It should ignore empty TLS secrets.
func TestCACompleter_reconcileSecret_emptySecret(t *testing.T) {
	ctrl := CACompleter{
		Log: zap.New(),
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-secret",
			Namespace: "test-namespace",
		},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{
			"ca.crt": nil,
			"tls.crt": nil,
		},
	}

	updatedSecret, err := ctrl.reconcileSecret(secret)
	assert.NoError(t, err)
	assert.Empty(t, updatedSecret)
}

// It should error on an invalid TLS secret.
func TestCACompleter_reconcileSecret_invalidCert(t *testing.T) {
	ctrl := CACompleter{
		Log: zap.New(),
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-secret",
			Namespace: "test-namespace",
		},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{
			"ca.crt": nil,
			"tls.crt": []byte(certs[0][:len(certs[0])-100]), // partial cert
		},
	}

	updatedSecret, err := ctrl.reconcileSecret(secret)
	assert.EqualError(t, err, ErrInvalidCertChain)
	assert.Empty(t, updatedSecret)
}

// certs is a valid certificate chain
var certs = []string{
	`-----BEGIN CERTIFICATE-----
MIIFYTCCBEmgAwIBAgISAxfhI8R2WPt76qybWCGzde6rMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTEyMTkxMTIwMTdaFw0y
MDAzMTgxMTIwMTdaMB8xHTAbBgNVBAMTFGNhcHRuLmVyd2ludmFuZXlrLm5sMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsedAij/KXGZR/F4ifVMPhpzH
nUwYehh+UtAsJwQ9NmLyB90Jw/SGZv/LKBLsxx5L15vR41LUCOnQPd4wAmmJ2jRW
LPAYDZ0sOvf3BhKCwTW6kROwHBkunmP6Kn06uwcwHPsRFlQ7xu9adBS5q3kue8hj
2bOejtaM86ykmDVG+XCDN8vVPpEWJuE0IVzDMokUCQVK/5zdIRRO7zJnMZU/VrCm
+1Idm+jJXNVXwE/FgC3k9H4M+nh9VnEKPhXQySmKvHMZqCgb3ITbuL8miGoTaWhp
2oebxYmHbghyk7eFRsr76Cv4P2fYFWe2B3snfFgXC79G2ilm1ghmkSmLxyH6NwID
AQABo4ICajCCAmYwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT70a4kd2GgUjR4NtIN
UnQGqZG59zAfBgNVHSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBvBggrBgEF
BQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5j
cnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5j
cnlwdC5vcmcvMB8GA1UdEQQYMBaCFGNhcHRuLmVyd2ludmFuZXlrLm5sMEwGA1Ud
IARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0
dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBQYKKwYBBAHWeQIEAgSB9gSB8wDx
AHcAb1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RMAAAFvHhn83AAABAMA
SDBGAiEAtBW14sq2Jy6Z7mCdnhq7Zgeh8LC370PPKoOHgWFP92ECIQDhnSHuI3pz
xbk29B/GPqqJy9XVCToCPAKqGz4F7ctqqgB2AAe3XBvlfWj/8bDGHSMVx7rmV3xX
lLdq7rxhOhpp06IcAAABbx4Z/PQAAAQDAEcwRQIhAN+fYcIfq0J5tdKJ8SPkVk77
bJnxV0aTxsiIjev2OLK+AiBuw92zJhpMC0KyX6fP66dj/OpOGQ75GxY2d94Mg0uA
iDANBgkqhkiG9w0BAQsFAAOCAQEAlwzfkkKOrtbiB4ZQQCqn10s7Y4VrXPiCsoZE
DtpB6VRZjBeiicSdK3c2XfKweHCWrH62QxVrPRvwrFYOGe0EXOt+jy3I/o0Kp4IY
hEVS23iu28hwCzP/v65ICY0FQeQfFu7K9k3eNYD4tW2U8W2yQNxSUom15s4+zyJ+
hwIa/ys0+ZQKLsu8nPzfLGvpA67LK1c61VLNXzSW9+YXUGIgBIa1bHkzK1ujELba
Cwj53ZmHXEAiRaPXV5V0NspVmwWamqk54hnO2xWQWCAxQG2oqBAOpjpnMGp9/7XQ
LudiyAzEXPe0D8PRXhyRlLF4J5+jN7LwrePp0geMqfKtH0XHhg==
-----END CERTIFICATE-----
`,
	`-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
`}