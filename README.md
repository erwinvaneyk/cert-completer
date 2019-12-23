# Cert Completer

Cert Completer is a small Kubernetes operator that ensures that all TLS secrets 
have a valid `ca.crt`.

It addresses a specific issue with the (Let's Encrypt) ACME provider in 
[cert-manager](https://github.com/jetstack/cert-manager), where certificates 
are lacking a CA in the `ca.crt` key of the generated secret. Although issues 
have been raised to fill the `ca.crt` 
(see [#2111](https://github.com/jetstack/cert-manager/issues/2111) and 
[#1571](https://github.com/jetstack/cert-manager/issues/1571)), it is not clear 
if and when these issues will be resolved. Cert Completer is an attempt to patch 
this issue immediately regardless of the cert-manager version.

To provide each TLS secret with a `ca.crt`, the operator parses the certificate 
chain in `tls.crt`. It uses the last (top-most) certificate in this chain for 
`ca.crt`. Although this does not guarantee that `ca.crt` contains a root CA, it 
does guarantee that the CA present is valid for the TLS secret. 

## Installation

Using pre-built resources:
```bash
kubectl apply -f https://raw.githubusercontent.com/erwinvaneyk/cert-completer/master/cert-completer.yaml
```

Using Kustomize (requires kubectl > 1.15):
```bash
kubectl apply -k github.com/erwinvaneyk/cert-completer//config/default
```

Clone and modify [./config/default/kustomization.yaml] for alternative, 
custom deployments.