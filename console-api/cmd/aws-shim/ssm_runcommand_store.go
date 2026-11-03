// SSM Run Command state (#347 item 22), in the SSM store's Postgres: the commands SendCommand sent, one
// invocation per (command, instance), and the managed instances — the VMs whose metadata agent polls the
// shim's command channel (vmcommands.go). An invocation is Pending until its instance's agent takes it
// (InProgress), then Success, Failed or TimedOut as the agent reports; one its agent never takes is
// TimedOut (DeliveryTimedOut) after the command's TimeoutSeconds, and one the agent took but never
// reported is TimedOut (ExecutionTimedOut) after its executionTimeout. Commands are kept 30 days, as AWS.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// ssmOutputCap is the most of each output stream an invocation keeps (GetCommandInvocation's 24,000
// characters).
const ssmOutputCap = 24000

type ssmCommand struct {
	ID, Document, Comment, RequestedBy string
	Parameters                         map[string][]string
	Targets                            []map[string]any
	InstanceIDs                        []string
	TimeoutSeconds                     int
	MaxConcurrency, MaxErrors          string
	Requested, Expires                 time.Time
}

type ssmInvocation struct {
	CommandID, InstanceID, Status, StatusDetails, Stdout, Stderr string
	ResponseCode, ExecutionTimeout                               int
	Delivered, Finished                                          sql.NullTime
	Command                                                      ssmCommand
}

type ssmManagedInstance struct {
	InstanceID, Namespace, VMName, Role                                  string
	AgentVersion, PlatformName, PlatformVersion, IPAddress, ComputerName string
	Registered, LastPing                                                 time.Time
}

func (s *ssmStore) ensureRunCommandSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS ssm_commands (
    command_id      text PRIMARY KEY,
    document_name   text NOT NULL,
    comment         text NOT NULL DEFAULT '',
    parameters      jsonb NOT NULL DEFAULT '{}',
    targets         jsonb NOT NULL DEFAULT '[]',
    timeout_seconds int NOT NULL,
    max_concurrency text NOT NULL DEFAULT '50',
    max_errors      text NOT NULL DEFAULT '0',
    requested_by    text NOT NULL DEFAULT '',
    requested_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ssm_invocations (
    command_id        text NOT NULL REFERENCES ssm_commands (command_id) ON DELETE CASCADE,
    instance_id       text NOT NULL,
    status            text NOT NULL DEFAULT 'Pending',
    status_details    text NOT NULL DEFAULT 'Pending',
    response_code     int NOT NULL DEFAULT -1,
    stdout            text NOT NULL DEFAULT '',
    stderr            text NOT NULL DEFAULT '',
    execution_timeout int NOT NULL DEFAULT 3600,
    delivered_at      timestamptz,
    finished_at       timestamptz,
    PRIMARY KEY (command_id, instance_id)
);
CREATE INDEX IF NOT EXISTS ssm_invocations_open ON ssm_invocations (instance_id) WHERE status IN ('Pending', 'InProgress');
CREATE TABLE IF NOT EXISTS ssm_managed_instances (
    instance_id      text PRIMARY KEY,
    namespace        text NOT NULL,
    vm_name          text NOT NULL,
    role             text NOT NULL DEFAULT '',
    agent_version    text NOT NULL DEFAULT '',
    platform_name    text NOT NULL DEFAULT '',
    platform_version text NOT NULL DEFAULT '',
    ip_address       text NOT NULL DEFAULT '',
    computer_name    text NOT NULL DEFAULT '',
    registered       timestamptz NOT NULL DEFAULT now(),
    last_ping        timestamptz NOT NULL DEFAULT now()
);`)
	return err
}

// capOutput keeps the first ssmOutputCap characters of s (valid UTF-8, without the NUL Postgres text refuses).
func capOutput(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if !utf8.ValidString(s) {
		s = string([]rune(s))
	}
	if utf8.RuneCountInString(s) <= ssmOutputCap {
		return s
	}
	return string([]rune(s)[:ssmOutputCap])
}

// ping records a managed instance's agent (registering it on first contact).
func (s *ssmStore) ping(ctx context.Context, m ssmManagedInstance) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ssm_managed_instances
    (instance_id, namespace, vm_name, role, agent_version, platform_name, platform_version, ip_address, computer_name)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (instance_id) DO UPDATE SET namespace=$2, vm_name=$3, role=$4, agent_version=$5, platform_name=$6,
    platform_version=$7, ip_address=$8, computer_name=$9, last_ping=now()`,
		m.InstanceID, m.Namespace, m.VMName, m.Role, m.AgentVersion, m.PlatformName, m.PlatformVersion, m.IPAddress, m.ComputerName)
	return err
}

// managedInstances is every registered instance, by id.
func (s *ssmStore) managedInstances(ctx context.Context) (map[string]ssmManagedInstance, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT instance_id, namespace, vm_name, role, agent_version, platform_name, platform_version,
    ip_address, computer_name, registered, last_ping FROM ssm_managed_instances`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ssmManagedInstance{}
	for rows.Next() {
		var m ssmManagedInstance
		if err := rows.Scan(&m.InstanceID, &m.Namespace, &m.VMName, &m.Role, &m.AgentVersion, &m.PlatformName, &m.PlatformVersion,
			&m.IPAddress, &m.ComputerName, &m.Registered, &m.LastPing); err != nil {
			return nil, err
		}
		out[m.InstanceID] = m
	}
	return out, rows.Err()
}

// createCommand records a command and a Pending invocation for each of its instances.
func (s *ssmStore) createCommand(ctx context.Context, c ssmCommand, execTimeout int) (ssmCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer func() { _ = tx.Rollback() }()
	params, _ := json.Marshal(c.Parameters)
	targets, _ := json.Marshal(c.Targets)
	if err := tx.QueryRowContext(ctx, `INSERT INTO ssm_commands (command_id, document_name, comment, parameters, targets, timeout_seconds,
    max_concurrency, max_errors, requested_by, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now() + make_interval(secs => $6)) RETURNING requested_at, expires_at`,
		c.ID, c.Document, c.Comment, string(params), string(targets), c.TimeoutSeconds, c.MaxConcurrency, c.MaxErrors, c.RequestedBy).
		Scan(&c.Requested, &c.Expires); err != nil {
		return c, err
	}
	for _, id := range c.InstanceIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ssm_invocations (command_id, instance_id, execution_timeout) VALUES ($1,$2,$3)`,
			c.ID, id, execTimeout); err != nil {
			return c, err
		}
	}
	return c, tx.Commit()
}

// sweep ends the invocations that can no longer finish, and forgets commands older than 30 days.
func (s *ssmStore) sweep(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE ssm_invocations i SET status='TimedOut', status_details='DeliveryTimedOut', finished_at=now()
    FROM ssm_commands c WHERE i.command_id=c.command_id AND i.status='Pending' AND c.expires_at < now();
UPDATE ssm_invocations SET status='TimedOut', status_details='ExecutionTimedOut', finished_at=now()
    WHERE status='InProgress' AND delivered_at + make_interval(secs => execution_timeout + 120) < now();
DELETE FROM ssm_commands WHERE requested_at < now() - interval '30 days';`)
	return err
}

// ssmDelivery is a command as an instance's agent receives it.
type ssmDelivery struct {
	CommandID    string              `json:"CommandId"`
	DocumentName string              `json:"DocumentName"`
	Parameters   map[string][]string `json:"Parameters"`
}

// claimPending hands instance's Pending invocations to its agent: each becomes InProgress, once.
func (s *ssmStore) claimPending(ctx context.Context, instanceID string) ([]ssmDelivery, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE ssm_invocations i SET status='InProgress', status_details='InProgress', delivered_at=now()
    FROM ssm_commands c
    WHERE i.command_id=c.command_id AND i.instance_id=$1 AND i.status='Pending' AND c.expires_at >= now()
    RETURNING i.command_id, c.document_name, c.parameters, i.execution_timeout`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ssmDelivery
	for rows.Next() {
		var d ssmDelivery
		var params []byte
		var timeout int
		if err := rows.Scan(&d.CommandID, &d.DocumentName, &params, &timeout); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(params, &d.Parameters)
		if d.Parameters == nil {
			d.Parameters = map[string][]string{}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// hasPending reports whether instance has an invocation its agent has not taken yet.
func (s *ssmStore) hasPending(ctx context.Context, instanceID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM ssm_invocations WHERE instance_id=$1 AND status='Pending'`, instanceID).Scan(&n)
	return n > 0, err
}

var errInvocationNotRunning = errors.New("the invocation is not in progress")

// finish records an InProgress invocation's result, reported by its own instance's agent.
func (s *ssmStore) finish(ctx context.Context, commandID, instanceID, status string, code int, stdout, stderr string) error {
	details := status
	if status == "TimedOut" {
		details = "ExecutionTimedOut"
	}
	res, err := s.db.ExecContext(ctx, `UPDATE ssm_invocations SET status=$3, status_details=$4, response_code=$5, stdout=$6, stderr=$7, finished_at=now()
    WHERE command_id=$1 AND instance_id=$2 AND status='InProgress'`, commandID, instanceID, status, details, code, capOutput(stdout), capOutput(stderr))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errInvocationNotRunning
	}
	return nil
}

const invocationColumns = `i.command_id, i.instance_id, i.status, i.status_details, i.response_code, i.stdout, i.stderr, i.execution_timeout,
    i.delivered_at, i.finished_at, c.document_name, c.comment, c.parameters, c.targets, c.timeout_seconds, c.max_concurrency, c.max_errors,
    c.requested_by, c.requested_at, c.expires_at`

func scanInvocation(row interface{ Scan(...any) error }) (ssmInvocation, error) {
	var v ssmInvocation
	var params, targets []byte
	err := row.Scan(&v.CommandID, &v.InstanceID, &v.Status, &v.StatusDetails, &v.ResponseCode, &v.Stdout, &v.Stderr, &v.ExecutionTimeout,
		&v.Delivered, &v.Finished, &v.Command.Document, &v.Command.Comment, &params, &targets, &v.Command.TimeoutSeconds,
		&v.Command.MaxConcurrency, &v.Command.MaxErrors, &v.Command.RequestedBy, &v.Command.Requested, &v.Command.Expires)
	if err != nil {
		return v, err
	}
	v.Command.ID = v.CommandID
	_ = json.Unmarshal(params, &v.Command.Parameters)
	_ = json.Unmarshal(targets, &v.Command.Targets)
	return v, nil
}

// invocations lists invocations, of one command and/or one instance when given, newest command first.
func (s *ssmStore) invocations(ctx context.Context, commandID, instanceID string) ([]ssmInvocation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+invocationColumns+` FROM ssm_invocations i JOIN ssm_commands c ON c.command_id=i.command_id
    WHERE ($1='' OR i.command_id=$1) AND ($2='' OR i.instance_id=$2) ORDER BY c.requested_at DESC, i.command_id, i.instance_id`, commandID, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ssmInvocation
	for rows.Next() {
		v, err := scanInvocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// commandExists reports whether a command is recorded.
func (s *ssmStore) commandExists(ctx context.Context, commandID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM ssm_commands WHERE command_id=$1`, commandID).Scan(&n)
	return n > 0, err
}
