// Route 53 Resolver state for the aws-shim: DNS Firewall domain lists, rule groups, rules and their VPC
// associations, each VPC's firewall configuration, and query logging configurations and their VPC
// associations. Shares the SQS/KMS Postgres.
//
// Every row carries its owner: "" for the management account (where an account-scoped door always kept
// its resources), the member account's id for a member account's (accountKey's rule). Ids are random, so
// they never collide across accounts; the owner is what keeps one account from reading another's.
//
// The VPC resolver (vpcresolver.go) reads one VPC's configuration with resolverConfig. The store bumps a
// generation on every write, so the resolver drops what it cached the moment this process changes it;
// another replica's writes reach it within its cache's few seconds.
package main

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/lib/pq"
)

type r53rStore struct {
	db  *sql.DB
	gen atomic.Int64 // bumped on every write
}

// r53rError is a Route 53 Resolver error as AWS answers it: its code, message and, for a missing or
// existing resource, the resource type (the error's ResourceType member).
type r53rError struct {
	Code, Message, ResourceType, FieldName string
}

func (e *r53rError) Error() string { return e.Code + ": " + e.Message }

func r53rNotFound(resourceType, msg string) *r53rError {
	return &r53rError{Code: "ResourceNotFoundException", Message: msg, ResourceType: resourceType}
}

func r53rValidation(msg string) *r53rError {
	return &r53rError{Code: "ValidationException", Message: msg}
}

func r53rConflict(msg string) *r53rError { return &r53rError{Code: "ConflictException", Message: msg} }

type r53rDomainList struct {
	ID, Owner, Name, CreatorRequestID string
	DomainCount                       int
	Created, Modified                 time.Time
}

type r53rRuleGroup struct {
	ID, Owner, Name, CreatorRequestID string
	RuleCount                         int
	Created, Modified                 time.Time
}

// r53rRule is a DNS Firewall rule. A rule is identified, as on AWS, by its rule group, its domain list and
// its query type (DeleteFirewallRule's FirewallDomainListId and Qtype).
type r53rRule struct {
	GroupID, DomainListID, Qtype, Name string
	Priority                           int
	Action, BlockResponse              string
	BlockOverrideDomain                string
	BlockOverrideDNSType               string
	BlockOverrideTTL                   *int
	Redirection                        string // INSPECT_REDIRECTION_DOMAIN | TRUST_REDIRECTION_DOMAIN
	CreatorRequestID                   string
	Created, Modified                  time.Time
}

type r53rAssociation struct {
	ID, Owner, GroupID, VpcID, Name string
	Priority                        int
	MutationProtection              string
	CreatorRequestID                string
	Created, Modified               time.Time
}

type r53rQueryLogConfig struct {
	ID, Owner, Name, DestinationARN, CreatorRequestID string
	AssociationCount                                  int
	Created                                           time.Time
}

type r53rQueryLogAssociation struct {
	ID, Owner, ConfigID, VpcID string
	Created                    time.Time
}

func (s *r53rStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS r53r_domain_lists (
    id                 text PRIMARY KEY,
    owner              text NOT NULL,
    name               text NOT NULL,
    creator_request_id text NOT NULL,
    created            timestamptz NOT NULL DEFAULT now(),
    modified           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT r53r_domain_lists_request UNIQUE (owner, creator_request_id)
);
CREATE TABLE IF NOT EXISTS r53r_domains (
    list_id text NOT NULL REFERENCES r53r_domain_lists(id) ON DELETE CASCADE,
    domain  text NOT NULL,
    PRIMARY KEY (list_id, domain)
);
CREATE TABLE IF NOT EXISTS r53r_rule_groups (
    id                 text PRIMARY KEY,
    owner              text NOT NULL,
    name               text NOT NULL,
    creator_request_id text NOT NULL,
    created            timestamptz NOT NULL DEFAULT now(),
    modified           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT r53r_rule_groups_request UNIQUE (owner, creator_request_id)
);
CREATE TABLE IF NOT EXISTS r53r_rules (
    group_id                text NOT NULL REFERENCES r53r_rule_groups(id),
    domain_list_id          text NOT NULL REFERENCES r53r_domain_lists(id),
    qtype                   text NOT NULL DEFAULT '',
    name                    text NOT NULL,
    priority                int  NOT NULL,
    action                  text NOT NULL,
    block_response          text NOT NULL DEFAULT '',
    block_override_domain   text NOT NULL DEFAULT '',
    block_override_dns_type text NOT NULL DEFAULT '',
    block_override_ttl      int,
    redirection             text NOT NULL DEFAULT 'INSPECT_REDIRECTION_DOMAIN',
    creator_request_id      text NOT NULL,
    created                 timestamptz NOT NULL DEFAULT now(),
    modified                timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT r53r_rules_pkey PRIMARY KEY (group_id, domain_list_id, qtype),
    CONSTRAINT r53r_rules_priority UNIQUE (group_id, priority),
    CONSTRAINT r53r_rules_request UNIQUE (group_id, creator_request_id)
);
CREATE TABLE IF NOT EXISTS r53r_rule_group_associations (
    id                  text PRIMARY KEY,
    owner               text NOT NULL,
    group_id            text NOT NULL REFERENCES r53r_rule_groups(id),
    vpc_id              text NOT NULL,
    name                text NOT NULL,
    priority            int  NOT NULL,
    mutation_protection text NOT NULL DEFAULT 'DISABLED',
    creator_request_id  text NOT NULL,
    created             timestamptz NOT NULL DEFAULT now(),
    modified            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT r53r_assoc_group_vpc UNIQUE (owner, vpc_id, group_id),
    CONSTRAINT r53r_assoc_priority UNIQUE (owner, vpc_id, priority),
    CONSTRAINT r53r_assoc_request UNIQUE (owner, creator_request_id)
);
CREATE TABLE IF NOT EXISTS r53r_firewall_configs (
    owner     text NOT NULL,
    vpc_id    text NOT NULL,
    fail_open text NOT NULL,
    PRIMARY KEY (owner, vpc_id)
);
CREATE TABLE IF NOT EXISTS r53r_query_log_configs (
    id                 text PRIMARY KEY,
    owner              text NOT NULL,
    name               text NOT NULL,
    destination_arn    text NOT NULL,
    creator_request_id text NOT NULL,
    created            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT r53r_qlc_request UNIQUE (owner, creator_request_id)
);
CREATE TABLE IF NOT EXISTS r53r_query_log_associations (
    id        text PRIMARY KEY,
    owner     text NOT NULL,
    config_id text NOT NULL REFERENCES r53r_query_log_configs(id),
    vpc_id    text NOT NULL,
    created   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT r53r_qla_config_vpc UNIQUE (config_id, vpc_id)
);
CREATE TABLE IF NOT EXISTS r53r_tags (
    resource_id text NOT NULL,
    key         text NOT NULL,
    value       text NOT NULL,
    PRIMARY KEY (resource_id, key)
);`)
	return err
}

// generation changes whenever this process writes.
func (s *r53rStore) generation() int64 {
	if s == nil {
		return 0
	}
	return s.gen.Load()
}

func (s *r53rStore) changed() { s.gen.Add(1) }

// uniqueViolation is the constraint a Postgres unique violation names, "" for any other error.
func uniqueViolation(err error) string {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return pqErr.Constraint
	}
	return ""
}

// --- domain lists ---

const r53rDomainListCols = `l.id, l.owner, l.name, l.creator_request_id, l.created, l.modified,
	(SELECT count(*) FROM r53r_domains d WHERE d.list_id = l.id)`

func scanDomainList(row interface{ Scan(...any) error }) (r53rDomainList, error) {
	var l r53rDomainList
	err := row.Scan(&l.ID, &l.Owner, &l.Name, &l.CreatorRequestID, &l.Created, &l.Modified, &l.DomainCount)
	return l, err
}

// createDomainList stores a new domain list, or answers the one an earlier request with the same
// CreatorRequestId made (created false), as AWS does for a retried request.
func (s *r53rStore) createDomainList(ctx context.Context, l r53rDomainList, tags map[string]string) (r53rDomainList, bool, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO r53r_domain_lists (id, owner, name, creator_request_id) VALUES ($1,$2,$3,$4)`,
		l.ID, l.Owner, l.Name, l.CreatorRequestID)
	if uniqueViolation(err) == "r53r_domain_lists_request" {
		prev, err := scanDomainList(s.db.QueryRowContext(ctx, `SELECT `+r53rDomainListCols+` FROM r53r_domain_lists l
			WHERE l.owner=$1 AND l.creator_request_id=$2`, l.Owner, l.CreatorRequestID))
		return prev, false, err
	}
	if err != nil {
		return r53rDomainList{}, false, err
	}
	if err := s.setTags(ctx, l.ID, tags); err != nil {
		return r53rDomainList{}, false, err
	}
	s.changed()
	got, _, err := s.getDomainList(ctx, l.Owner, l.ID)
	return got, true, err
}

func (s *r53rStore) getDomainList(ctx context.Context, owner, id string) (r53rDomainList, bool, error) {
	l, err := scanDomainList(s.db.QueryRowContext(ctx, `SELECT `+r53rDomainListCols+` FROM r53r_domain_lists l
		WHERE l.owner=$1 AND l.id=$2`, owner, id))
	if err == sql.ErrNoRows {
		return r53rDomainList{}, false, nil
	}
	return l, err == nil, err
}

func (s *r53rStore) listDomainLists(ctx context.Context, owner string) ([]r53rDomainList, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+r53rDomainListCols+` FROM r53r_domain_lists l
		WHERE l.owner=$1 ORDER BY l.created, l.id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []r53rDomainList
	for rows.Next() {
		l, err := scanDomainList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// deleteDomainList deletes a domain list no rule uses (a rule's list is refused, as on AWS).
func (s *r53rStore) deleteDomainList(ctx context.Context, owner, id string) (r53rDomainList, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rDomainList{}, err
	}
	defer func() { _ = tx.Rollback() }()
	l, err := scanDomainList(tx.QueryRowContext(ctx, `SELECT `+r53rDomainListCols+` FROM r53r_domain_lists l
		WHERE l.owner=$1 AND l.id=$2 FOR UPDATE`, owner, id))
	if err == sql.ErrNoRows {
		return r53rDomainList{}, r53rNotFound("FIREWALL_DOMAIN_LIST", "The domain list '"+id+"' does not exist.")
	} else if err != nil {
		return r53rDomainList{}, err
	}
	var groups []string
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT group_id FROM r53r_rules WHERE domain_list_id=$1 ORDER BY group_id`, id)
	if err != nil {
		return r53rDomainList{}, err
	}
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			rows.Close()
			return r53rDomainList{}, err
		}
		groups = append(groups, g)
	}
	rows.Close()
	if len(groups) > 0 {
		return r53rDomainList{}, r53rConflict("The domain list '" + id + "' is used by a rule in rule group " +
			strings.Join(groups, ", ") + ": delete the rule first.")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_domain_lists WHERE id=$1`, id); err != nil {
		return r53rDomainList{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_tags WHERE resource_id=$1`, id); err != nil {
		return r53rDomainList{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rDomainList{}, err
	}
	s.changed()
	return l, nil
}

// r53rMaxDomainsPerList is the most domains one list holds (AWS's default quota per account is 100,000
// domains; here it is per list).
const r53rMaxDomainsPerList = 100000

// updateDomains applies UpdateFirewallDomains' operation to a domain list (domains already validated and
// normalized).
func (s *r53rStore) updateDomains(ctx context.Context, owner, id, op string, domains []string) (r53rDomainList, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rDomainList{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM r53r_domain_lists WHERE owner=$1 AND id=$2 FOR UPDATE`, owner, id).Scan(&name); err == sql.ErrNoRows {
		return r53rDomainList{}, r53rNotFound("FIREWALL_DOMAIN_LIST", "The domain list '"+id+"' does not exist.")
	} else if err != nil {
		return r53rDomainList{}, err
	}
	switch op {
	case "REPLACE":
		if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_domains WHERE list_id=$1`, id); err != nil {
			return r53rDomainList{}, err
		}
		fallthrough
	case "ADD":
		if len(domains) > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO r53r_domains (list_id, domain) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`,
				id, pq.Array(domains)); err != nil {
				return r53rDomainList{}, err
			}
		}
	case "REMOVE":
		if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_domains WHERE list_id=$1 AND domain = ANY($2::text[])`, id, pq.Array(domains)); err != nil {
			return r53rDomainList{}, err
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM r53r_domains WHERE list_id=$1`, id).Scan(&n); err != nil {
		return r53rDomainList{}, err
	}
	if n > r53rMaxDomainsPerList {
		return r53rDomainList{}, &r53rError{Code: "LimitExceededException", ResourceType: "FIREWALL_DOMAIN",
			Message: "A domain list holds at most 100000 domains."}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE r53r_domain_lists SET modified=now() WHERE id=$1`, id); err != nil {
		return r53rDomainList{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rDomainList{}, err
	}
	s.changed()
	l, _, err := s.getDomainList(ctx, owner, id)
	return l, err
}

func (s *r53rStore) listDomains(ctx context.Context, owner, id string) ([]string, bool, error) {
	if _, ok, err := s.getDomainList(ctx, owner, id); err != nil || !ok {
		return nil, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM r53r_domains WHERE list_id=$1 ORDER BY domain COLLATE "C"`, id)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, false, err
		}
		out = append(out, d)
	}
	return out, true, rows.Err()
}

// --- rule groups ---

const r53rRuleGroupCols = `g.id, g.owner, g.name, g.creator_request_id, g.created, g.modified,
	(SELECT count(*) FROM r53r_rules r WHERE r.group_id = g.id)`

func scanRuleGroup(row interface{ Scan(...any) error }) (r53rRuleGroup, error) {
	var g r53rRuleGroup
	err := row.Scan(&g.ID, &g.Owner, &g.Name, &g.CreatorRequestID, &g.Created, &g.Modified, &g.RuleCount)
	return g, err
}

func (s *r53rStore) createRuleGroup(ctx context.Context, g r53rRuleGroup, tags map[string]string) (r53rRuleGroup, bool, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO r53r_rule_groups (id, owner, name, creator_request_id) VALUES ($1,$2,$3,$4)`,
		g.ID, g.Owner, g.Name, g.CreatorRequestID)
	if uniqueViolation(err) == "r53r_rule_groups_request" {
		prev, err := scanRuleGroup(s.db.QueryRowContext(ctx, `SELECT `+r53rRuleGroupCols+` FROM r53r_rule_groups g
			WHERE g.owner=$1 AND g.creator_request_id=$2`, g.Owner, g.CreatorRequestID))
		return prev, false, err
	}
	if err != nil {
		return r53rRuleGroup{}, false, err
	}
	if err := s.setTags(ctx, g.ID, tags); err != nil {
		return r53rRuleGroup{}, false, err
	}
	s.changed()
	got, _, err := s.getRuleGroup(ctx, g.Owner, g.ID)
	return got, true, err
}

func (s *r53rStore) getRuleGroup(ctx context.Context, owner, id string) (r53rRuleGroup, bool, error) {
	g, err := scanRuleGroup(s.db.QueryRowContext(ctx, `SELECT `+r53rRuleGroupCols+` FROM r53r_rule_groups g
		WHERE g.owner=$1 AND g.id=$2`, owner, id))
	if err == sql.ErrNoRows {
		return r53rRuleGroup{}, false, nil
	}
	return g, err == nil, err
}

func (s *r53rStore) listRuleGroups(ctx context.Context, owner string) ([]r53rRuleGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+r53rRuleGroupCols+` FROM r53r_rule_groups g
		WHERE g.owner=$1 ORDER BY g.created, g.id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []r53rRuleGroup
	for rows.Next() {
		g, err := scanRuleGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// deleteRuleGroup deletes a rule group that holds no rules and is associated with no VPC, as AWS requires.
func (s *r53rStore) deleteRuleGroup(ctx context.Context, owner, id string) (r53rRuleGroup, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rRuleGroup{}, err
	}
	defer func() { _ = tx.Rollback() }()
	g, err := scanRuleGroup(tx.QueryRowContext(ctx, `SELECT `+r53rRuleGroupCols+` FROM r53r_rule_groups g
		WHERE g.owner=$1 AND g.id=$2 FOR UPDATE`, owner, id))
	if err == sql.ErrNoRows {
		return r53rRuleGroup{}, r53rNotFound("FIREWALL_RULE_GROUP", "The rule group '"+id+"' does not exist.")
	} else if err != nil {
		return r53rRuleGroup{}, err
	}
	var vpcs []string
	rows, err := tx.QueryContext(ctx, `SELECT vpc_id FROM r53r_rule_group_associations WHERE group_id=$1 ORDER BY vpc_id`, id)
	if err != nil {
		return r53rRuleGroup{}, err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return r53rRuleGroup{}, err
		}
		vpcs = append(vpcs, v)
	}
	rows.Close()
	if len(vpcs) > 0 {
		return r53rRuleGroup{}, r53rConflict("The rule group '" + id + "' is associated with " + strings.Join(vpcs, ", ") +
			": disassociate it first (DisassociateFirewallRuleGroup).")
	}
	if g.RuleCount > 0 {
		return r53rRuleGroup{}, r53rConflict("The rule group '" + id + "' still has rules: delete them first (DeleteFirewallRule).")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_rule_groups WHERE id=$1`, id); err != nil {
		return r53rRuleGroup{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_tags WHERE resource_id=$1`, id); err != nil {
		return r53rRuleGroup{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rRuleGroup{}, err
	}
	s.changed()
	return g, nil
}

// --- rules ---

const r53rRuleCols = `group_id, domain_list_id, qtype, name, priority, action, block_response, block_override_domain,
	block_override_dns_type, block_override_ttl, redirection, creator_request_id, created, modified`

func scanRule(row interface{ Scan(...any) error }) (r53rRule, error) {
	var r r53rRule
	var ttl sql.NullInt64
	err := row.Scan(&r.GroupID, &r.DomainListID, &r.Qtype, &r.Name, &r.Priority, &r.Action, &r.BlockResponse,
		&r.BlockOverrideDomain, &r.BlockOverrideDNSType, &ttl, &r.Redirection, &r.CreatorRequestID, &r.Created, &r.Modified)
	if ttl.Valid {
		v := int(ttl.Int64)
		r.BlockOverrideTTL = &v
	}
	return r, err
}

func nullableInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// r53rMaxRulesPerGroup is AWS's quota of rules per rule group.
const r53rMaxRulesPerGroup = 100

// lockRuleGroup locks the caller's rule group for a change to its rules; a missing group is AWS's
// ResourceNotFoundException.
func lockRuleGroup(ctx context.Context, tx *sql.Tx, owner, groupID string) error {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM r53r_rule_groups WHERE owner=$1 AND id=$2 FOR UPDATE`, owner, groupID).Scan(&id)
	if err == sql.ErrNoRows {
		return r53rNotFound("FIREWALL_RULE_GROUP", "The rule group '"+groupID+"' does not exist.")
	}
	return err
}

func rulesOfGroup(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, groupID string) ([]r53rRule, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+r53rRuleCols+` FROM r53r_rules WHERE group_id=$1 ORDER BY priority`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []r53rRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// createRule adds a rule to the caller's rule group (validated: validR53RRule), or answers the rule an
// earlier request with the same CreatorRequestId made.
func (s *r53rStore) createRule(ctx context.Context, owner string, r r53rRule) (r53rRule, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rRule{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockRuleGroup(ctx, tx, owner, r.GroupID); err != nil {
		return r53rRule{}, err
	}
	var listOK bool
	if err := tx.QueryRowContext(ctx, `SELECT true FROM r53r_domain_lists WHERE owner=$1 AND id=$2`, owner, r.DomainListID).Scan(&listOK); err == sql.ErrNoRows {
		return r53rRule{}, r53rNotFound("FIREWALL_DOMAIN_LIST", "The domain list '"+r.DomainListID+"' does not exist "+
			"(AWS managed domain lists are not served here: use a domain list of your own).")
	} else if err != nil {
		return r53rRule{}, err
	}
	rules, err := rulesOfGroup(ctx, tx, r.GroupID)
	if err != nil {
		return r53rRule{}, err
	}
	for _, x := range rules {
		if x.CreatorRequestID == r.CreatorRequestID {
			return x, nil // a retried request
		}
	}
	if e := checkNewRule(rules, r, -1); e != nil {
		return r53rRule{}, e
	}
	if len(rules) >= r53rMaxRulesPerGroup {
		return r53rRule{}, &r53rError{Code: "LimitExceededException", ResourceType: "FIREWALL_RULE",
			Message: "A rule group holds at most 100 rules."}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO r53r_rules (group_id, domain_list_id, qtype, name, priority, action,
		block_response, block_override_domain, block_override_dns_type, block_override_ttl, redirection, creator_request_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		r.GroupID, r.DomainListID, r.Qtype, r.Name, r.Priority, r.Action, r.BlockResponse, r.BlockOverrideDomain,
		r.BlockOverrideDNSType, nullableInt(r.BlockOverrideTTL), r.Redirection, r.CreatorRequestID); err != nil {
		return r53rRule{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE r53r_rule_groups SET modified=now() WHERE id=$1`, r.GroupID); err != nil {
		return r53rRule{}, err
	}
	got, err := scanRule(tx.QueryRowContext(ctx, `SELECT `+r53rRuleCols+` FROM r53r_rules
		WHERE group_id=$1 AND domain_list_id=$2 AND qtype=$3`, r.GroupID, r.DomainListID, r.Qtype))
	if err != nil {
		return r53rRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rRule{}, err
	}
	s.changed()
	return got, nil
}

// checkNewRule is the uniqueness AWS keeps in a rule group: one rule per domain list and query type, and
// one rule per priority. skip is the index of the rule being replaced (-1 for a new one).
func checkNewRule(rules []r53rRule, r r53rRule, skip int) *r53rError {
	for i, x := range rules {
		if i == skip {
			continue
		}
		if x.DomainListID == r.DomainListID && strings.EqualFold(x.Qtype, r.Qtype) {
			what := "the domain list " + r.DomainListID
			if r.Qtype != "" {
				what += " and query type " + r.Qtype
			}
			return r53rValidation("The rule group " + r.GroupID + " already has a rule for " + what + ".")
		}
		if x.Priority == r.Priority {
			return r53rValidation("The rule group " + r.GroupID + " already has a rule with priority " +
				itoa(r.Priority) + ": each rule in a rule group needs a unique priority.")
		}
	}
	return nil
}

// locateRule finds the rule a request names by its domain list and its query type (DeleteFirewallRule's
// Qtype): with a query type, the list's rule for it; without one, the list's only rule, or its rule with no
// query type. byQtypeOrOnly is UpdateFirewallRule's reading, whose Qtype may be the rule's new query type:
// the list's rule for that query type if there is one, else the list's only rule.
func locateRule(rules []r53rRule, groupID, listID, qtype string, qtypeGiven, byQtypeOrOnly bool) (int, *r53rError) {
	var candidates []int
	for i, r := range rules {
		if r.DomainListID == listID {
			candidates = append(candidates, i)
		}
	}
	if qtypeGiven {
		for _, i := range candidates {
			if strings.EqualFold(rules[i].Qtype, qtype) {
				return i, nil
			}
		}
	}
	if !qtypeGiven || byQtypeOrOnly {
		if len(candidates) == 1 {
			return candidates[0], nil
		}
		if !qtypeGiven {
			for _, i := range candidates {
				if rules[i].Qtype == "" {
					return i, nil
				}
			}
		}
		if len(candidates) > 1 {
			return -1, r53rValidation("The rule group " + groupID + " has several rules for the domain list " + listID +
				": name the rule's Qtype.")
		}
	}
	return -1, r53rNotFound("FIREWALL_RULE", "The rule group '"+groupID+"' has no rule for the domain list '"+listID+"'.")
}

func (s *r53rStore) listRules(ctx context.Context, owner, groupID string) ([]r53rRule, bool, error) {
	if _, ok, err := s.getRuleGroup(ctx, owner, groupID); err != nil || !ok {
		return nil, false, err
	}
	rules, err := rulesOfGroup(ctx, s.db, groupID)
	return rules, true, err
}

// updateRule changes the rule a request names: change edits a copy, which is then checked (validR53RRule
// and the group's uniqueness) and stored in its place.
func (s *r53rStore) updateRule(ctx context.Context, owner, groupID, listID, qtype string, qtypeGiven bool,
	change func(*r53rRule) *r53rError) (r53rRule, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rRule{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockRuleGroup(ctx, tx, owner, groupID); err != nil {
		return r53rRule{}, err
	}
	rules, err := rulesOfGroup(ctx, tx, groupID)
	if err != nil {
		return r53rRule{}, err
	}
	i, e := locateRule(rules, groupID, listID, qtype, qtypeGiven, true)
	if e != nil {
		return r53rRule{}, e
	}
	old := rules[i]
	next := old
	if e := change(&next); e != nil {
		return r53rRule{}, e
	}
	if e := validR53RRule(&next); e != nil {
		return r53rRule{}, e
	}
	if e := checkNewRule(rules, next, i); e != nil {
		return r53rRule{}, e
	}
	if _, err := tx.ExecContext(ctx, `UPDATE r53r_rules SET qtype=$4, name=$5, priority=$6, action=$7, block_response=$8,
		block_override_domain=$9, block_override_dns_type=$10, block_override_ttl=$11, redirection=$12, modified=now()
		WHERE group_id=$1 AND domain_list_id=$2 AND qtype=$3`,
		groupID, old.DomainListID, old.Qtype, next.Qtype, next.Name, next.Priority, next.Action, next.BlockResponse,
		next.BlockOverrideDomain, next.BlockOverrideDNSType, nullableInt(next.BlockOverrideTTL), next.Redirection); err != nil {
		return r53rRule{}, err
	}
	got, err := scanRule(tx.QueryRowContext(ctx, `SELECT `+r53rRuleCols+` FROM r53r_rules
		WHERE group_id=$1 AND domain_list_id=$2 AND qtype=$3`, groupID, old.DomainListID, next.Qtype))
	if err != nil {
		return r53rRule{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE r53r_rule_groups SET modified=now() WHERE id=$1`, groupID); err != nil {
		return r53rRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rRule{}, err
	}
	s.changed()
	return got, nil
}

func (s *r53rStore) deleteRule(ctx context.Context, owner, groupID, listID, qtype string, qtypeGiven bool) (r53rRule, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rRule{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockRuleGroup(ctx, tx, owner, groupID); err != nil {
		return r53rRule{}, err
	}
	rules, err := rulesOfGroup(ctx, tx, groupID)
	if err != nil {
		return r53rRule{}, err
	}
	i, e := locateRule(rules, groupID, listID, qtype, qtypeGiven, false)
	if e != nil {
		return r53rRule{}, e
	}
	r := rules[i]
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_rules WHERE group_id=$1 AND domain_list_id=$2 AND qtype=$3`,
		groupID, r.DomainListID, r.Qtype); err != nil {
		return r53rRule{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE r53r_rule_groups SET modified=now() WHERE id=$1`, groupID); err != nil {
		return r53rRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rRule{}, err
	}
	s.changed()
	return r, nil
}

// --- rule group associations ---

const r53rAssocCols = `id, owner, group_id, vpc_id, name, priority, mutation_protection, creator_request_id, created, modified`

func scanAssoc(row interface{ Scan(...any) error }) (r53rAssociation, error) {
	var a r53rAssociation
	err := row.Scan(&a.ID, &a.Owner, &a.GroupID, &a.VpcID, &a.Name, &a.Priority, &a.MutationProtection,
		&a.CreatorRequestID, &a.Created, &a.Modified)
	return a, err
}

// associate associates a rule group with a VPC: one association per rule group and VPC, one per priority
// in a VPC, as AWS keeps them. A request with an earlier request's CreatorRequestId answers its
// association.
func (s *r53rStore) associate(ctx context.Context, a r53rAssociation, tags map[string]string) (r53rAssociation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rAssociation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if prev, err := scanAssoc(tx.QueryRowContext(ctx, `SELECT `+r53rAssocCols+` FROM r53r_rule_group_associations
		WHERE owner=$1 AND creator_request_id=$2`, a.Owner, a.CreatorRequestID)); err == nil {
		return prev, nil
	} else if err != sql.ErrNoRows {
		return r53rAssociation{}, err
	}
	if err := lockRuleGroup(ctx, tx, a.Owner, a.GroupID); err != nil {
		return r53rAssociation{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO r53r_rule_group_associations (id, owner, group_id, vpc_id, name, priority,
		mutation_protection, creator_request_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.ID, a.Owner, a.GroupID, a.VpcID, a.Name, a.Priority, a.MutationProtection, a.CreatorRequestID)
	switch uniqueViolation(err) {
	case "r53r_assoc_group_vpc":
		return r53rAssociation{}, r53rConflict("The rule group " + a.GroupID + " is already associated with " + a.VpcID + ".")
	case "r53r_assoc_priority":
		return r53rAssociation{}, r53rConflict("Another rule group is associated with " + a.VpcID + " at priority " +
			itoa(a.Priority) + ": each rule group associated with a VPC needs a unique priority.")
	}
	if err != nil {
		return r53rAssociation{}, err
	}
	if err := setTagsTx(ctx, tx, a.ID, tags); err != nil {
		return r53rAssociation{}, err
	}
	got, err := scanAssoc(tx.QueryRowContext(ctx, `SELECT `+r53rAssocCols+` FROM r53r_rule_group_associations WHERE id=$1`, a.ID))
	if err != nil {
		return r53rAssociation{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rAssociation{}, err
	}
	s.changed()
	return got, nil
}

func (s *r53rStore) getAssociation(ctx context.Context, owner, id string) (r53rAssociation, bool, error) {
	a, err := scanAssoc(s.db.QueryRowContext(ctx, `SELECT `+r53rAssocCols+` FROM r53r_rule_group_associations
		WHERE owner=$1 AND id=$2`, owner, id))
	if err == sql.ErrNoRows {
		return r53rAssociation{}, false, nil
	}
	return a, err == nil, err
}

func (s *r53rStore) listAssociations(ctx context.Context, owner string) ([]r53rAssociation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+r53rAssocCols+` FROM r53r_rule_group_associations
		WHERE owner=$1 ORDER BY vpc_id, priority, id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []r53rAssociation
	for rows.Next() {
		a, err := scanAssoc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// updateAssociation changes an association's name, priority or mutation protection (change edits a copy).
func (s *r53rStore) updateAssociation(ctx context.Context, owner, id string, change func(*r53rAssociation) *r53rError) (r53rAssociation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rAssociation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	a, err := scanAssoc(tx.QueryRowContext(ctx, `SELECT `+r53rAssocCols+` FROM r53r_rule_group_associations
		WHERE owner=$1 AND id=$2 FOR UPDATE`, owner, id))
	if err == sql.ErrNoRows {
		return r53rAssociation{}, r53rNotFound("FIREWALL_RULE_GROUP_ASSOCIATION", "The rule group association '"+id+"' does not exist.")
	} else if err != nil {
		return r53rAssociation{}, err
	}
	next := a
	if e := change(&next); e != nil {
		return r53rAssociation{}, e
	}
	_, err = tx.ExecContext(ctx, `UPDATE r53r_rule_group_associations SET name=$2, priority=$3, mutation_protection=$4,
		modified=now() WHERE id=$1`, id, next.Name, next.Priority, next.MutationProtection)
	if uniqueViolation(err) == "r53r_assoc_priority" {
		return r53rAssociation{}, r53rConflict("Another rule group is associated with " + a.VpcID + " at priority " +
			itoa(next.Priority) + ": each rule group associated with a VPC needs a unique priority.")
	}
	if err != nil {
		return r53rAssociation{}, err
	}
	got, err := scanAssoc(tx.QueryRowContext(ctx, `SELECT `+r53rAssocCols+` FROM r53r_rule_group_associations WHERE id=$1`, id))
	if err != nil {
		return r53rAssociation{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rAssociation{}, err
	}
	s.changed()
	return got, nil
}

// disassociate removes an association whose mutation protection is off.
func (s *r53rStore) disassociate(ctx context.Context, owner, id string) (r53rAssociation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rAssociation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	a, err := scanAssoc(tx.QueryRowContext(ctx, `SELECT `+r53rAssocCols+` FROM r53r_rule_group_associations
		WHERE owner=$1 AND id=$2 FOR UPDATE`, owner, id))
	if err == sql.ErrNoRows {
		return r53rAssociation{}, r53rNotFound("FIREWALL_RULE_GROUP_ASSOCIATION", "The rule group association '"+id+"' does not exist.")
	} else if err != nil {
		return r53rAssociation{}, err
	}
	if a.MutationProtection == "ENABLED" {
		return r53rAssociation{}, r53rValidation("The rule group association " + id + " has mutation protection enabled: " +
			"disable it (UpdateFirewallRuleGroupAssociation MutationProtection DISABLED) before you disassociate it.")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_rule_group_associations WHERE id=$1`, id); err != nil {
		return r53rAssociation{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_tags WHERE resource_id=$1`, id); err != nil {
		return r53rAssociation{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rAssociation{}, err
	}
	s.changed()
	return a, nil
}

// --- firewall configs ---

// r53rDefaultFailOpen is AWS's default: fail open is disabled, so a failure blocks (fails closed).
const r53rDefaultFailOpen = "DISABLED"

func (s *r53rStore) failOpen(ctx context.Context, owner, vpcID string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT fail_open FROM r53r_firewall_configs WHERE owner=$1 AND vpc_id=$2`, owner, vpcID).Scan(&v)
	if err == sql.ErrNoRows {
		return r53rDefaultFailOpen, nil
	}
	return v, err
}

func (s *r53rStore) setFailOpen(ctx context.Context, owner, vpcID, v string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO r53r_firewall_configs (owner, vpc_id, fail_open) VALUES ($1,$2,$3)
		ON CONFLICT (owner, vpc_id) DO UPDATE SET fail_open=EXCLUDED.fail_open`, owner, vpcID, v)
	if err == nil {
		s.changed()
	}
	return err
}

// failOpens is every VPC's stored setting of the owner (a VPC with none has the default).
func (s *r53rStore) failOpens(ctx context.Context, owner string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT vpc_id, fail_open FROM r53r_firewall_configs WHERE owner=$1`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var vpc, v string
		if err := rows.Scan(&vpc, &v); err != nil {
			return nil, err
		}
		out[vpc] = v
	}
	return out, rows.Err()
}

// --- query logging ---

const r53rQLCCols = `c.id, c.owner, c.name, c.destination_arn, c.creator_request_id, c.created,
	(SELECT count(*) FROM r53r_query_log_associations a WHERE a.config_id = c.id)`

func scanQLC(row interface{ Scan(...any) error }) (r53rQueryLogConfig, error) {
	var c r53rQueryLogConfig
	err := row.Scan(&c.ID, &c.Owner, &c.Name, &c.DestinationARN, &c.CreatorRequestID, &c.Created, &c.AssociationCount)
	return c, err
}

func (s *r53rStore) createQueryLogConfig(ctx context.Context, c r53rQueryLogConfig, tags map[string]string) (r53rQueryLogConfig, bool, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO r53r_query_log_configs (id, owner, name, destination_arn, creator_request_id)
		VALUES ($1,$2,$3,$4,$5)`, c.ID, c.Owner, c.Name, c.DestinationARN, c.CreatorRequestID)
	if uniqueViolation(err) == "r53r_qlc_request" {
		prev, err := scanQLC(s.db.QueryRowContext(ctx, `SELECT `+r53rQLCCols+` FROM r53r_query_log_configs c
			WHERE c.owner=$1 AND c.creator_request_id=$2`, c.Owner, c.CreatorRequestID))
		return prev, false, err
	}
	if err != nil {
		return r53rQueryLogConfig{}, false, err
	}
	if err := s.setTags(ctx, c.ID, tags); err != nil {
		return r53rQueryLogConfig{}, false, err
	}
	s.changed()
	got, _, err := s.getQueryLogConfig(ctx, c.Owner, c.ID)
	return got, true, err
}

func (s *r53rStore) getQueryLogConfig(ctx context.Context, owner, id string) (r53rQueryLogConfig, bool, error) {
	c, err := scanQLC(s.db.QueryRowContext(ctx, `SELECT `+r53rQLCCols+` FROM r53r_query_log_configs c
		WHERE c.owner=$1 AND c.id=$2`, owner, id))
	if err == sql.ErrNoRows {
		return r53rQueryLogConfig{}, false, nil
	}
	return c, err == nil, err
}

func (s *r53rStore) listQueryLogConfigs(ctx context.Context, owner string) ([]r53rQueryLogConfig, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+r53rQLCCols+` FROM r53r_query_log_configs c
		WHERE c.owner=$1 ORDER BY c.created, c.id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []r53rQueryLogConfig
	for rows.Next() {
		c, err := scanQLC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// deleteQueryLogConfig deletes a configuration no VPC is associated with, as AWS requires.
func (s *r53rStore) deleteQueryLogConfig(ctx context.Context, owner, id string) (r53rQueryLogConfig, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rQueryLogConfig{}, err
	}
	defer func() { _ = tx.Rollback() }()
	c, err := scanQLC(tx.QueryRowContext(ctx, `SELECT `+r53rQLCCols+` FROM r53r_query_log_configs c
		WHERE c.owner=$1 AND c.id=$2 FOR UPDATE`, owner, id))
	if err == sql.ErrNoRows {
		return r53rQueryLogConfig{}, r53rNotFound("RESOLVER_QUERY_LOG_CONFIG", "The query logging configuration '"+id+"' does not exist.")
	} else if err != nil {
		return r53rQueryLogConfig{}, err
	}
	if c.AssociationCount > 0 {
		return r53rQueryLogConfig{}, &r53rError{Code: "InvalidRequestException",
			Message: "The query logging configuration " + id + " is associated with " + itoa(c.AssociationCount) +
				" VPC(s): disassociate them first (DisassociateResolverQueryLogConfig)."}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_query_log_configs WHERE id=$1`, id); err != nil {
		return r53rQueryLogConfig{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM r53r_tags WHERE resource_id=$1`, id); err != nil {
		return r53rQueryLogConfig{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rQueryLogConfig{}, err
	}
	s.changed()
	return c, nil
}

const r53rQLACols = `id, owner, config_id, vpc_id, created`

func scanQLA(row interface{ Scan(...any) error }) (r53rQueryLogAssociation, error) {
	var a r53rQueryLogAssociation
	err := row.Scan(&a.ID, &a.Owner, &a.ConfigID, &a.VpcID, &a.Created)
	return a, err
}

func (s *r53rStore) associateQueryLog(ctx context.Context, a r53rQueryLogAssociation) (r53rQueryLogAssociation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r53rQueryLogAssociation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM r53r_query_log_configs WHERE owner=$1 AND id=$2 FOR UPDATE`, a.Owner, a.ConfigID).Scan(&id); err == sql.ErrNoRows {
		return r53rQueryLogAssociation{}, r53rNotFound("RESOLVER_QUERY_LOG_CONFIG", "The query logging configuration '"+a.ConfigID+"' does not exist.")
	} else if err != nil {
		return r53rQueryLogAssociation{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO r53r_query_log_associations (id, owner, config_id, vpc_id) VALUES ($1,$2,$3,$4)`,
		a.ID, a.Owner, a.ConfigID, a.VpcID)
	if uniqueViolation(err) == "r53r_qla_config_vpc" {
		return r53rQueryLogAssociation{}, &r53rError{Code: "ResourceExistsException", ResourceType: "RESOLVER_QUERY_LOG_CONFIG_ASSOCIATION",
			Message: "The query logging configuration " + a.ConfigID + " is already associated with " + a.VpcID + "."}
	}
	if err != nil {
		return r53rQueryLogAssociation{}, err
	}
	got, err := scanQLA(tx.QueryRowContext(ctx, `SELECT `+r53rQLACols+` FROM r53r_query_log_associations WHERE id=$1`, a.ID))
	if err != nil {
		return r53rQueryLogAssociation{}, err
	}
	if err := tx.Commit(); err != nil {
		return r53rQueryLogAssociation{}, err
	}
	s.changed()
	return got, nil
}

func (s *r53rStore) disassociateQueryLog(ctx context.Context, owner, configID, vpcID string) (r53rQueryLogAssociation, error) {
	a, err := scanQLA(s.db.QueryRowContext(ctx, `DELETE FROM r53r_query_log_associations
		WHERE owner=$1 AND config_id=$2 AND vpc_id=$3 RETURNING `+r53rQLACols, owner, configID, vpcID))
	if err == sql.ErrNoRows {
		return r53rQueryLogAssociation{}, r53rNotFound("RESOLVER_QUERY_LOG_CONFIG_ASSOCIATION",
			"The query logging configuration '"+configID+"' is not associated with '"+vpcID+"'.")
	} else if err != nil {
		return r53rQueryLogAssociation{}, err
	}
	s.changed()
	return a, nil
}

func (s *r53rStore) getQueryLogAssociation(ctx context.Context, owner, id string) (r53rQueryLogAssociation, bool, error) {
	a, err := scanQLA(s.db.QueryRowContext(ctx, `SELECT `+r53rQLACols+` FROM r53r_query_log_associations
		WHERE owner=$1 AND id=$2`, owner, id))
	if err == sql.ErrNoRows {
		return r53rQueryLogAssociation{}, false, nil
	}
	return a, err == nil, err
}

func (s *r53rStore) listQueryLogAssociations(ctx context.Context, owner string) ([]r53rQueryLogAssociation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+r53rQLACols+` FROM r53r_query_log_associations
		WHERE owner=$1 ORDER BY created, id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []r53rQueryLogAssociation
	for rows.Next() {
		a, err := scanQLA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- tags ---

func setTagsTx(ctx context.Context, tx interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, resourceID string, tags map[string]string) error {
	for k, v := range tags {
		if _, err := tx.ExecContext(ctx, `INSERT INTO r53r_tags (resource_id, key, value) VALUES ($1,$2,$3)
			ON CONFLICT (resource_id, key) DO UPDATE SET value=EXCLUDED.value`, resourceID, k, v); err != nil {
			return err
		}
	}
	return nil
}

func (s *r53rStore) setTags(ctx context.Context, resourceID string, tags map[string]string) error {
	return setTagsTx(ctx, s.db, resourceID, tags)
}

func (s *r53rStore) untag(ctx context.Context, resourceID string, keys []string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM r53r_tags WHERE resource_id=$1 AND key = ANY($2::text[])`, resourceID, pq.Array(keys))
	return err
}

func (s *r53rStore) tags(ctx context.Context, resourceID string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM r53r_tags WHERE resource_id=$1`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// --- the VPC resolver's read ---

// vpcResolverConfig is what the VPC resolver applies to one VPC's queries.
type vpcResolverConfig struct {
	FailOpen  string             // the VPC's FirewallFailOpen
	Rules     []resolverRule     // its DNS Firewall rules, in evaluation order
	QueryLogs []resolverQueryLog // where its queries are logged
}

// resolverRule is one DNS Firewall rule as the resolver evaluates it.
type resolverRule struct {
	GroupID, DomainListID string
	AssociationPriority   int
	Priority              int
	Domains               []string // the domain list's domain specifications
	Action, BlockResponse string
	BlockOverrideDomain   string
	BlockOverrideDNSType  string
	BlockOverrideTTL      int
	Qtype                 string // "" for every query type
	Redirection           string
}

// resolverQueryLog is one query logging configuration associated with the VPC.
type resolverQueryLog struct {
	ConfigID, LogGroupARN string
}

// resolverConfig is the Route 53 Resolver configuration of account's VPC vpcID: its firewall fail-open
// setting, the rules of the rule groups associated with it — ordered by association priority, then rule
// priority, as DNS Firewall evaluates them — and its query log destinations.
func (s *r53rStore) resolverConfig(ctx context.Context, account, vpcID string) (vpcResolverConfig, error) {
	if s == nil || s.db == nil {
		return vpcResolverConfig{}, errors.New("the Route 53 Resolver store is not configured")
	}
	owner := r53rOwnerOf(account)
	failOpen, err := s.failOpen(ctx, owner, vpcID)
	if err != nil {
		return vpcResolverConfig{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT a.group_id, a.priority, r.domain_list_id, r.priority, r.action, r.block_response, r.block_override_domain,
       r.block_override_dns_type, r.block_override_ttl, r.qtype, r.redirection
  FROM r53r_rule_group_associations a JOIN r53r_rules r ON r.group_id = a.group_id
 WHERE a.owner=$1 AND a.vpc_id=$2`, owner, vpcID)
	if err != nil {
		return vpcResolverConfig{}, err
	}
	var rules []resolverRule
	lists := map[string]bool{}
	for rows.Next() {
		var r resolverRule
		var ttl sql.NullInt64
		if err := rows.Scan(&r.GroupID, &r.AssociationPriority, &r.DomainListID, &r.Priority, &r.Action, &r.BlockResponse,
			&r.BlockOverrideDomain, &r.BlockOverrideDNSType, &ttl, &r.Qtype, &r.Redirection); err != nil {
			rows.Close()
			return vpcResolverConfig{}, err
		}
		r.BlockOverrideTTL = int(ttl.Int64)
		rules = append(rules, r)
		lists[r.DomainListID] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return vpcResolverConfig{}, err
	}
	domains := map[string][]string{}
	if len(lists) > 0 {
		ids := make([]string, 0, len(lists))
		for id := range lists {
			ids = append(ids, id)
		}
		drows, err := s.db.QueryContext(ctx, `SELECT list_id, domain FROM r53r_domains WHERE list_id = ANY($1::text[])`, pq.Array(ids))
		if err != nil {
			return vpcResolverConfig{}, err
		}
		for drows.Next() {
			var id, d string
			if err := drows.Scan(&id, &d); err != nil {
				drows.Close()
				return vpcResolverConfig{}, err
			}
			domains[id] = append(domains[id], d)
		}
		drows.Close()
		if err := drows.Err(); err != nil {
			return vpcResolverConfig{}, err
		}
	}
	qrows, err := s.db.QueryContext(ctx, `SELECT c.id, c.destination_arn FROM r53r_query_log_associations a
		JOIN r53r_query_log_configs c ON c.id = a.config_id WHERE a.owner=$1 AND a.vpc_id=$2 ORDER BY c.id`, owner, vpcID)
	if err != nil {
		return vpcResolverConfig{}, err
	}
	var logs []resolverQueryLog
	for qrows.Next() {
		var q resolverQueryLog
		if err := qrows.Scan(&q.ConfigID, &q.LogGroupARN); err != nil {
			qrows.Close()
			return vpcResolverConfig{}, err
		}
		logs = append(logs, q)
	}
	qrows.Close()
	if err := qrows.Err(); err != nil {
		return vpcResolverConfig{}, err
	}
	return buildResolverConfig(failOpen, rules, domains, logs), nil
}

// buildResolverConfig orders a VPC's rules as DNS Firewall evaluates them: the rule groups by their
// association's priority, then each group's rules by their own priority (the lowest first, each time).
func buildResolverConfig(failOpen string, rules []resolverRule, domains map[string][]string, logs []resolverQueryLog) vpcResolverConfig {
	out := make([]resolverRule, len(rules))
	copy(out, rules)
	for i := range out {
		out[i].Domains = domains[out[i].DomainListID]
		if out[i].Redirection == "" {
			out[i].Redirection = "INSPECT_REDIRECTION_DOMAIN"
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AssociationPriority != out[j].AssociationPriority {
			return out[i].AssociationPriority < out[j].AssociationPriority
		}
		return out[i].Priority < out[j].Priority
	})
	if failOpen == "" {
		failOpen = r53rDefaultFailOpen
	}
	return vpcResolverConfig{FailOpen: failOpen, Rules: out, QueryLogs: logs}
}

// r53rOwnerOf is the store owner of account's resources: "" for the management account, the account's id
// for a member account.
func r53rOwnerOf(account string) string {
	if awsidentity.Current().IsManagement(account) {
		return ""
	}
	return account
}
