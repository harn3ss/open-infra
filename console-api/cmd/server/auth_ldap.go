package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAP / Active Directory sign-in (AUTH_MODE=ldap).
//
// Authenticates console users against a directory — typically the Samba AD DC that
// `kind: Directory` provisions, so the platform's own AD is the console's identity
// provider. Configured entirely by env (see docs/auth.md):
//
//	LDAP_HOST            dc.example.com (or a Service DNS name)
//	LDAP_DOMAIN          EXAMPLE.COM — used to build the UPN and the base DN
//	LDAP_BIND_USER       account used to look the user up (UPN or sAMAccountName)
//	LDAP_BIND_PASSWORD   its password
//	LDAP_USER_BASE_DN    optional; defaults to the domain's base DN
//	LDAP_ADMIN_GROUP     AD group -> admin role      (default: openinfra-admins)
//	LDAP_POWERUSER_GROUP AD group -> poweruser role  (default: openinfra-powerusers)
//	LDAP_READONLY_GROUP  AD group -> readonly role   (default: openinfra-readers)
//
// The local `root` account in the console-auth Secret always keeps working as
// break-glass, so a directory outage can't lock you out of your own console.

type ldapConfig struct {
	host, domain       string
	bindUser, bindPass string
	userBaseDN         string
	adminGroup         string
	powerGroup         string
	readGroup          string
}

func loadLDAPConfig() ldapConfig {
	c := ldapConfig{
		host:       getenv("LDAP_HOST", ""),
		domain:     getenv("LDAP_DOMAIN", ""),
		bindUser:   getenv("LDAP_BIND_USER", ""),
		bindPass:   getenv("LDAP_BIND_PASSWORD", ""),
		userBaseDN: getenv("LDAP_USER_BASE_DN", ""),
		adminGroup: getenv("LDAP_ADMIN_GROUP", "openinfra-admins"),
		powerGroup: getenv("LDAP_POWERUSER_GROUP", "openinfra-powerusers"),
		readGroup:  getenv("LDAP_READONLY_GROUP", "openinfra-readers"),
	}
	if c.userBaseDN == "" && c.domain != "" {
		c.userBaseDN = domainToBaseDN(c.domain)
	}
	return c
}

// dialLDAP prefers LDAPS and falls back to plain LDAP (Samba AD's self-signed
// cert is the norm on a private cluster network).
func dialLDAP(host string) (*ldap.Conn, error) {
	l, err := ldap.DialURL("ldaps://"+host+":636",
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err == nil {
		return l, nil
	}
	return ldap.DialURL("ldap://" + host + ":389")
}

// verifyLDAP resolves the user, verifies their password by binding AS them, and
// maps their AD group membership to a console role.
func verifyLDAP(c ldapConfig, username, password string) (string, bool) {
	if c.host == "" || password == "" || username == "" {
		return "", false
	}

	l, err := dialLDAP(c.host)
	if err != nil {
		return "", false
	}
	defer l.Close()

	// 1. Bind as the lookup account.
	bindUser := c.bindUser
	if bindUser != "" && !strings.Contains(bindUser, "@") && !strings.Contains(bindUser, "=") && c.domain != "" {
		bindUser = bindUser + "@" + c.domain
	}
	if err := l.Bind(bindUser, c.bindPass); err != nil {
		return "", false
	}

	// 2. Find the user (by sAMAccountName or UPN) and read their groups.
	filter := fmt.Sprintf("(&(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))",
		ldap.EscapeFilter(username), ldap.EscapeFilter(username))
	res, err := l.Search(ldap.NewSearchRequest(
		c.userBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		filter, []string{"dn", "memberOf", "sAMAccountName"}, nil,
	))
	if err != nil || len(res.Entries) != 1 {
		return "", false
	}
	entry := res.Entries[0]

	// 3. Verify the password by binding as that user. An empty password would be
	//    an unauthenticated bind (which LDAP accepts) — already rejected above.
	if err := l.Bind(entry.DN, password); err != nil {
		return "", false
	}

	return ldapRole(c, entry.GetAttributeValues("memberOf")), true
}

// ldapRole maps AD group membership to a console role, most privileged wins.
// No matching group -> readonly (least privilege), so merely existing in the
// directory never grants write access.
func ldapRole(c ldapConfig, memberOf []string) string {
	has := func(group string) bool {
		if group == "" {
			return false
		}
		want := strings.ToLower("cn=" + group + ",")
		for _, dn := range memberOf {
			if strings.HasPrefix(strings.ToLower(dn), want) {
				return true
			}
		}
		return false
	}
	switch {
	case has(c.adminGroup):
		return "admin"
	case has(c.powerGroup):
		return "poweruser"
	default:
		return "readonly"
	}
}
