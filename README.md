# RcodeZero cert-manager ACME webhook

[![Release Charts](https://github.com/nic-at/certmanager-webhook-rcodezero/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/nic-at/certmanager-webhook-rcodezero/actions/workflows/release.yml)

Cert-manager webhook plugin for the  [RcodeZero](https://www.rcodezero.at) [API](https://my.rcodezero.at/openapi)

## Installation

### cert-manager

Follow the [instructions](https://cert-manager.io/docs/installation/) using the cert-manager documentation to install it within your cluster.

### Webhook

#### Using public helm chart
```bash
helm repo add cert-manager-webhook-powerdns https://nic-at.github.io/cert-manager-webhook-rcodezero
# Replace the groupName value with your desired domain
helm install --namespace cert-manager cert-manager-webhook-rcodezero cert-manager-webhook-rcodezero/cert-manager-webhook-rcodezero --set groupName=acme.yourdomain.tld
```

## Issuer/ClusterIssuer

An example issuer (generate the RcodeZero ACME API token via [my.rcodezero.at](https://my.rcodezero.at) (Note: The token needs the `acme`-Permission)):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rcodezero-api-token
type: Opaque
data:
  token: RCODEZERO_ACME_API_TOKEN_BASE64
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    email: certificates@example.ca
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.mydomain.tld
            solverName: rcodezero
            config:
              # Reference to the Kubernetes secret containing the API key.
              apiKeySecretRef:
                name: rcodezero-api-token
                key: token

```

And then you can issue a cert:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: test-example-ca
  namespace: default
spec:
  secretName: example-com-tls
  dnsNames:
  - example.tld
  - www.example.tld
  issuerRef:
    name: letsencrypt-staging
    kind: Issuer
    group: cert-manager.io
```
