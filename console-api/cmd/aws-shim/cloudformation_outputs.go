// Stack Outputs + cross-stack Exports for the CloudFormation doorway (#347).
//
// The engine evaluates a template's Outputs against the deployed stack when it reaches *_COMPLETE and
// persists them on the stack record (cfn/outputs.go). The doorway serves them the AWS way:
//
//   - DescribeStacks returns each stack's Outputs (OutputKey / OutputValue / Description / ExportName);
//   - an Output with an Export.Name is a cross-stack export in this doorway's namespace: ListExports lists
//     them, and every template the doorway evaluates (validate, create, update, change sets) resolves
//     Fn::ImportValue against them;
//   - AWS's export rules hold: an export name another stack already exports refuses the create/update,
//     and a stack (or an update) that would remove an export another stack imports is refused.
package main

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
)

// stackExports is the doorway's export registry: export name -> value and -> exporting stack.
type stackExports struct {
	values map[string]string
	owners map[string]string
}

// exportsFrom collects the exports of every stack record except `exclude` (a stack can't import its own
// exports). Only a record that completed carries Outputs, so a failed/in-progress stack exports nothing.
func exportsFrom(recs []*cfn.StackRecord, exclude string) stackExports {
	ex := stackExports{values: map[string]string{}, owners: map[string]string{}}
	for _, rec := range recs {
		if rec == nil || rec.Name == exclude {
			continue
		}
		for _, o := range rec.Outputs {
			if o.ExportName == "" {
				continue
			}
			ex.values[o.ExportName] = o.OutputValue
			ex.owners[o.ExportName] = rec.Name
		}
	}
	return ex
}

// exportsFor returns the namespace's export registry, excluding stack `exclude`.
func (h *cfnDoorway) exportsFor(ctx context.Context, exclude string) stackExports {
	return exportsFrom(h.allRecords(ctx), exclude)
}

// optsFor is opts with the namespace's exports supplied for Fn::ImportValue — for every operation that
// evaluates a template.
func (h *cfnDoorway) optsFor(name string, params map[string]string, ex stackExports) cfn.DeployOptions {
	o := h.opts(name, params)
	o.Exports = ex.values
	return o
}

// exportCollision returns a refusal message when the template would export a name another stack already
// exports (AWS: "Export with name X is already exported by stack Y"), else "".
func exportCollision(body string, params map[string]string, ex stackExports, stack string) string {
	names, err := cfn.TemplateExportNames([]byte(body), params, ex.values, stack)
	if err != nil {
		return ""
	}
	for _, n := range names {
		if owner, taken := ex.owners[n]; taken {
			return "Export with name " + n + " is already exported by stack " + owner + "."
		}
	}
	return ""
}

// exportsInUse returns a refusal message when removing `removed` exports of stack `stack` would break
// another stack's Fn::ImportValue (AWS: "Export X cannot be deleted as it is in use by Y"), else "".
func exportsInUse(recs []*cfn.StackRecord, stack string, removed []string) string {
	for _, n := range removed {
		var users []string
		for _, rec := range recs {
			if rec == nil || rec.Name == stack {
				continue
			}
			for _, imp := range rec.Imports {
				if imp == n {
					users = append(users, rec.Name)
				}
			}
		}
		if len(users) > 0 {
			sort.Strings(users)
			return "Export " + n + " cannot be deleted as it is in use by " + strings.Join(users, ", ") + "."
		}
	}
	return ""
}

// exportGuards applies AWS's export rules to a create (current nil) or update of stack `stack`: an export
// name another stack already owns refuses, and so does an update that drops an export another stack
// imports. "" = allowed.
func (h *cfnDoorway) exportGuards(ctx context.Context, current *cfn.StackRecord, body string, params map[string]string, ex stackExports, stack string) string {
	if msg := exportCollision(body, params, ex, stack); msg != "" {
		return msg
	}
	if current == nil {
		return ""
	}
	return exportsInUse(h.allRecords(ctx), stack, removedExports(current, body, params, ex, stack))
}

// exportNames returns a record's export names.
func exportNames(rec *cfn.StackRecord) []string {
	var out []string
	for _, o := range rec.Outputs {
		if o.ExportName != "" {
			out = append(out, o.ExportName)
		}
	}
	return out
}

// removedExports returns the exports the current record has that the new template no longer exports.
func removedExports(current *cfn.StackRecord, body string, params map[string]string, ex stackExports, stack string) []string {
	next, err := cfn.TemplateExportNames([]byte(body), params, ex.values, stack)
	if err != nil {
		return nil
	}
	keep := map[string]bool{}
	for _, n := range next {
		keep[n] = true
	}
	var out []string
	for _, n := range exportNames(current) {
		if !keep[n] {
			out = append(out, n)
		}
	}
	return out
}

// outputsXML renders a record's Outputs as the DescribeStacks <Outputs> member ("" when there are none).
func outputsXML(rec *cfn.StackRecord) string {
	if len(rec.Outputs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<Outputs>")
	for _, o := range rec.Outputs {
		b.WriteString("<member>")
		b.WriteString("<OutputKey>" + xesc(o.OutputKey) + "</OutputKey>")
		b.WriteString("<OutputValue>" + xesc(o.OutputValue) + "</OutputValue>")
		if o.Description != "" {
			b.WriteString("<Description>" + xesc(o.Description) + "</Description>")
		}
		if o.ExportName != "" {
			b.WriteString("<ExportName>" + xesc(o.ExportName) + "</ExportName>")
		}
		b.WriteString("</member>")
	}
	b.WriteString("</Outputs>")
	return b.String()
}

// listExports serves ListExports: every export in the namespace, by name.
func (h *cfnDoorway) listExports(w http.ResponseWriter, r *http.Request, requestID string) {
	ex := h.exportsFor(r.Context(), "")
	names := make([]string, 0, len(ex.values))
	for n := range ex.values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString("<member>")
		b.WriteString("<ExportingStackId>" + xesc(h.liveStackID(r.Context(), ex.owners[n])) + "</ExportingStackId>")
		b.WriteString("<Name>" + xesc(n) + "</Name>")
		b.WriteString("<Value>" + xesc(h.queueURLsFor(r, ex.values[n])) + "</Value>")
		b.WriteString("</member>")
	}
	h.writeResult(w, requestID, "ListExports", "<Exports>"+b.String()+"</Exports>")
}

// logOutputs records why any Output was omitted once a stack operation completes (they are also on the
// stack record, outputsOmitted).
func (h *cfnDoorway) logOutputs(op, stack string, rec *cfn.StackRecord) {
	if rec == nil || h.logger == nil {
		return
	}
	for _, o := range rec.OutputsOmitted {
		h.logger.Info("cfn stack Output omitted (its value did not resolve)", "op", op, "stack", stack, "output", o.OutputKey, "reason", o.Reason)
	}
}
