// EC2 key pairs (#347 item 24): ImportKeyPair, CreateKeyPair, DescribeKeyPairs and DeleteKeyPair, kept in
// the shim's Postgres (the SQS/SSM store). A key pair is a name and an SSH public key: an instance's KeyName
// carries that key into its kind: VirtualMachine's spec.sshKey (the CloudFormation front door reads the key
// pairs into its deploy Capabilities, cfn/translate_keyname.go), and cloud-init authorizes it for the
// image's login user on first boot, as EC2 does.
//
// As on AWS: CreateKeyPair generates the key and returns its private half once (KeyMaterial), never kept;
// ImportKeyPair takes the public half only. Fingerprints are AWS's: for an RSA key it created, the SHA-1
// of the PKCS#8 private key; for an imported RSA key, the MD5 of the public key (RFC 4716); for ED25519,
// the SHA-256 of the public key (OpenSSH 6.8, base64).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type ec2KeyStore struct{ db *sql.DB }

type ec2KeyPair struct {
	Name, ID, Type, Fingerprint, PublicKey string
	Tags                                   map[string]string
	Created                                time.Time
}

var errKeyPairExists = errors.New("key pair exists")

// Accounts: a key pair is its account's, and its name is unique within that account (the same name may be
// a key pair in two accounts, each its own). Each row records its account in the account column: empty for
// the management account (every key pair made before accounts, and every one it makes), the member
// account's id for a member's. A key pair's name may hold any printable ASCII, ":" included, so the account
// is a column of its own, never a prefix of the name. Its id (key-…) is unique across accounts.
func (s *ec2KeyStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS ec2_key_pairs (
    name        text PRIMARY KEY,
    key_pair_id text NOT NULL UNIQUE,
    key_type    text NOT NULL,
    fingerprint text NOT NULL,
    public_key  text NOT NULL,
    tags        jsonb NOT NULL DEFAULT '{}',
    created     timestamptz NOT NULL DEFAULT now()
);
-- The account a key pair belongs to ('' = the management account, which every earlier row is): the primary
-- key on name alone becomes (account, name), once.
ALTER TABLE ec2_key_pairs ADD COLUMN IF NOT EXISTS account text NOT NULL DEFAULT '';
DO $$
DECLARE pk text;
BEGIN
  SELECT conname INTO pk FROM pg_constraint
   WHERE conrelid = 'ec2_key_pairs'::regclass AND contype = 'p' AND array_length(conkey, 1) = 1;
  IF pk IS NOT NULL THEN
    EXECUTE format('ALTER TABLE ec2_key_pairs DROP CONSTRAINT %I', pk);
    ALTER TABLE ec2_key_pairs ADD PRIMARY KEY (account, name);
  END IF;
END $$;`)
	return err
}

// ec2KeyAccount is the account column of the caller's account's key pairs: "" for the management account
// (where every key pair always was), the member account's id for a member's.
func ec2KeyAccount(ctx context.Context) string {
	if !isMemberRequest(ctx) {
		return ""
	}
	return callerAccount(ctx)
}

// put records a key pair of the caller's account; errKeyPairExists when the account has one of that name.
func (s *ec2KeyStore) put(ctx context.Context, k ec2KeyPair) (ec2KeyPair, error) {
	tags, _ := json.Marshal(k.Tags)
	err := s.db.QueryRowContext(ctx, `INSERT INTO ec2_key_pairs (account, name, key_pair_id, key_type, fingerprint, public_key, tags)
VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (account, name) DO NOTHING RETURNING created`,
		ec2KeyAccount(ctx), k.Name, k.ID, k.Type, k.Fingerprint, k.PublicKey, string(tags)).Scan(&k.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return ec2KeyPair{}, errKeyPairExists
	}
	return k, err
}

// list is the caller's account's key pairs, by name.
func (s *ec2KeyStore) list(ctx context.Context) ([]ec2KeyPair, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, key_pair_id, key_type, fingerprint, public_key, tags, created FROM ec2_key_pairs
WHERE account=$1 ORDER BY name`, ec2KeyAccount(ctx))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ec2KeyPair
	for rows.Next() {
		var k ec2KeyPair
		var tags []byte
		if err := rows.Scan(&k.Name, &k.ID, &k.Type, &k.Fingerprint, &k.PublicKey, &tags, &k.Created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tags, &k.Tags)
		out = append(out, k)
	}
	return out, rows.Err()
}

// delete removes the caller's account's key pair named name or with id keyID; deleting one that does not
// exist succeeds, as on AWS (another account's key pair of that name or id is not the caller's, and is
// left as it is). It returns the id of the pair removed ("" for none).
func (s *ec2KeyStore) delete(ctx context.Context, name, keyID string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `DELETE FROM ec2_key_pairs WHERE account=$3 AND (($1 <> '' AND name=$1) OR ($2 <> '' AND key_pair_id=$2))
RETURNING key_pair_id`, name, keyID, ec2KeyAccount(ctx)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// publicKeys is every key pair of the account ctx acts in, its public key by name: the CloudFormation front
// door's Capabilities.KeyPairs (a stack's instance names a key pair of the stack's own account).
func (s *ec2KeyStore) publicKeys(ctx context.Context) (map[string]string, error) {
	all, err := s.list(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(all))
	for _, k := range all {
		out[k.Name] = k.PublicKey
	}
	return out, nil
}

// --- keys ---

// newKeyPairID is a key pair id in AWS's shape: key- and 17 hex digits.
func newKeyPairID() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return "key-" + hex.EncodeToString(b)[:17]
}

// parseImportedKey parses ImportKeyPair's PublicKeyMaterial: an OpenSSH public key line (what an
// id_*.pub file holds), base64 of one (the CLI's fileb:// sends the raw bytes, the SDKs base64), or a
// PEM/DER RSA public key. Returns the key in OpenSSH form, its type, and AWS's fingerprint for it.
func parseImportedKey(material string) (authorized, keyType, fingerprint string, err error) {
	raw := strings.TrimSpace(material)
	pub, err := parseAnyPublicKey(raw)
	if err != nil {
		if dec, derr := base64.StdEncoding.DecodeString(raw); derr == nil {
			pub, err = parseAnyPublicKey(strings.TrimSpace(string(dec)))
		}
	}
	if err != nil {
		return "", "", "", fmt.Errorf("Key is not in valid OpenSSH public key format")
	}
	switch pub.Type() {
	case ssh.KeyAlgoRSA:
		keyType, fingerprint = "rsa", colonHex(md5Sum(pub.Marshal()))
		if ck, ok := pub.(ssh.CryptoPublicKey); ok {
			if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < 1024 {
				return "", "", "", fmt.Errorf("Invalid key size: an RSA key must be at least 1024 bits")
			}
		}
	case ssh.KeyAlgoED25519:
		keyType, fingerprint = "ed25519", sha256Fingerprint(pub)
	default:
		return "", "", "", fmt.Errorf("Unsupported key type %s: EC2 key pairs are RSA or ED25519", pub.Type())
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), keyType, fingerprint, nil
}

func parseAnyPublicKey(s string) (ssh.PublicKey, error) {
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s)); err == nil {
		return pub, nil
	}
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			k, err = x509.ParsePKCS1PublicKey(blk.Bytes)
		}
		if err != nil {
			return nil, err
		}
		return ssh.NewPublicKey(k)
	}
	return nil, errors.New("not a public key")
}

// generateKeyPair makes a key for CreateKeyPair: its private half as AWS returns it (a PEM RSA key, or an
// OpenSSH ED25519 key), its public half in OpenSSH form, and AWS's fingerprint.
func generateKeyPair(keyType string) (privatePEM, authorized, fingerprint string, err error) {
	switch keyType {
	case "", "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", "", "", err
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", "", "", err
		}
		pub, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			return "", "", "", err
		}
		sum := sha1.Sum(pkcs8)
		priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		return string(priv), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), colonHex(sum[:]), nil
	case "ed25519":
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", "", err
		}
		blk, err := ssh.MarshalPrivateKey(sk, "")
		if err != nil {
			return "", "", "", err
		}
		pub, err := ssh.NewPublicKey(pk)
		if err != nil {
			return "", "", "", err
		}
		return string(pem.EncodeToMemory(blk)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), sha256Fingerprint(pub), nil
	}
	return "", "", "", fmt.Errorf("unsupported KeyType %q (rsa or ed25519)", keyType)
}

func md5Sum(b []byte) []byte { s := md5.Sum(b); return s[:] }

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(parts, ":")
}

// sha256Fingerprint is AWS's ED25519 fingerprint: base64 (padded) of the SHA-256 of the public key.
func sha256Fingerprint(pub ssh.PublicKey) string {
	s := sha256.Sum256(pub.Marshal())
	return base64.StdEncoding.EncodeToString(s[:])
}
