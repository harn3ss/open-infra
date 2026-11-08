// The instance identity key in OpenBao Transit (#359; signing_transit.go).
//
// With INSTANCE_IDENTITY_TRANSIT_KEY set to <mount>/<key> (openinfra/transit/instance-identity), documents
// are signed by an RSA Transit key that OpenBao holds and never exports, as AWS signs instance identity
// documents with a key no instance and no operator holds. Each key version has a certificate made from the
// version alone (identityCertTemplate), served at /v1/vm-identity/certificate.
//
// Rotation is the Transit key's rotation (`bao write -f openinfra/transit/keys/instance-identity/rotate`): the
// new version signs within a minute, and each replaced version keeps verifying for one document lifetime after
// its successor was made. The key the shim kept in Secret instance-identity-signing-key before is retired:
// its certificates are recorded in ConfigMap instance-identity-retired, verifying for one document lifetime,
// and the Secret is deleted.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// identityRetiredConfigMap records the public halves of the key that was in identityKeySecretName.
const identityRetiredConfigMap = "instance-identity-retired"

// identityCertTemplate is the certificate of a key version: its serial from the public key, valid from an
// hour before the version was created for ten years. Nothing in it is random.
func identityCertTemplate(pub *rsa.PublicKey, created time.Time) *x509.Certificate {
	created = created.UTC().Truncate(time.Second)
	return &x509.Certificate{
		SerialNumber: keySerial(pub),
		Subject:      pkix.Name{Organization: []string{"open-infra"}, CommonName: "open-infra instance identity"},
		NotBefore:    created.Add(-time.Hour),
		NotAfter:     created.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// identityLegacyPubs is the public halves in the Secret the key was kept in: its certificate and the
// retired ones still listed.
func identityLegacyPubs(data map[string][]byte) []signingPub {
	raw := append(append(append([]byte{}, data[identityCertFile]...), '\n'), data[identityRetiredFile]...)
	certs, _ := parseCertsPEM(raw)
	var out []signingPub
	for _, c := range certs {
		if rp, ok := c.PublicKey.(*rsa.PublicKey); ok {
			out = append(out, signingPub{pub: rp, cert: c})
		}
	}
	return out
}

// useTransit makes the signer sign with the Transit key.
func (s *identitySigner) useTransit(t *transitSigning) {
	t.lifetime = s.ttl
	t.cert = identityCertTemplate
	t.legacySecret, t.retiredCM, t.legacyPubs = s.name, identityRetiredConfigMap, identityLegacyPubs
	t.cs, t.ns, t.logger, t.now = s.cs, s.ns, s.logger, s.clock
	s.transit = t
}

// loadTransit is the key material with the key in Transit: the latest version signs; it, the versions
// replaced less than a document's lifetime ago and the retired key's record verify, with their certificates.
func (s *identitySigner) loadTransit(ctx context.Context) (*identityKeys, error) {
	k, err := s.transit.keys(ctx)
	if err != nil {
		return nil, err
	}
	out := &identityKeys{sign: k.sign, cert: k.current().cert, certPEM: k.certsPEM()}
	for _, p := range k.verify {
		out.pubs = append(out.pubs, p.pub)
	}
	return out, nil
}
