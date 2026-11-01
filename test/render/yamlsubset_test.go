package render

// A small YAML reader for rendered composition output, so tests can assert on structure (a pod's
// labels, a NetworkPolicy's selector) instead of matching strings. This module is stdlib-only, so
// it reads the subset the compositions emit: block mappings and sequences, flow collections
// ({…} and […], possibly over several lines), plain and quoted scalars, block scalars (| and >),
// and comments. Scalars stay strings. It is not a general YAML parser.

import (
	"fmt"
	"strconv"
	"strings"
)

// parseYAMLDocs splits rendered output on `---` lines and parses each non-empty document.
func parseYAMLDocs(s string) ([]map[string]any, error) {
	var docs []map[string]any
	var cur []string
	flush := func() error {
		p := &yamlParser{lines: cur}
		v, err := p.parseDoc()
		cur = nil
		if err != nil {
			return err
		}
		if m, ok := v.(map[string]any); ok && len(m) > 0 {
			docs = append(docs, m)
		}
		return nil
	}
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimRight(ln, " ") == "---" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		cur = append(cur, ln)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return docs, nil
}

type yamlParser struct {
	lines   []string
	i       int
	anchors map[string]any // `&name` values, for `*name` aliases (an XRD reuses a schema this way)
}

func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

// skip moves past blank and comment-only lines.
func (p *yamlParser) skip() {
	for p.i < len(p.lines) {
		t := strings.TrimSpace(p.lines[p.i])
		if t == "" || strings.HasPrefix(t, "#") {
			p.i++
			continue
		}
		return
	}
}

func (p *yamlParser) parseDoc() (any, error) {
	p.skip()
	if p.i >= len(p.lines) {
		return nil, nil
	}
	v, err := p.parseBlock(indentOf(p.lines[p.i]))
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected content %q", p.i+1, strings.TrimSpace(p.lines[p.i]))
	}
	return v, nil
}

func isSeqItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *yamlParser) parseBlock(ind int) (any, error) {
	p.skip()
	if p.i >= len(p.lines) {
		return nil, nil
	}
	if isSeqItem(strings.TrimSpace(p.lines[p.i])) {
		return p.parseSeq(ind)
	}
	return p.parseMap(ind)
}

func (p *yamlParser) parseMap(ind int) (map[string]any, error) {
	m := map[string]any{}
	for {
		p.skip()
		if p.i >= len(p.lines) {
			return m, nil
		}
		ln := p.lines[p.i]
		if indentOf(ln) != ind {
			if indentOf(ln) > ind {
				return nil, fmt.Errorf("line %d: unexpected indent: %q", p.i+1, strings.TrimSpace(ln))
			}
			return m, nil
		}
		t := strings.TrimSpace(ln)
		if isSeqItem(t) {
			return m, nil
		}
		key, rest, ok := splitKey(t)
		if !ok {
			return nil, fmt.Errorf("line %d: expected `key: value`, got %q", p.i+1, t)
		}
		v, err := p.parseValue(ind, rest)
		if err != nil {
			return nil, err
		}
		m[key] = v
	}
}

// parseValue parses what follows `key:` (rest), advancing past it. ind is the key's indent.
func (p *yamlParser) parseValue(ind int, rest string) (any, error) {
	rest = stripComment(rest)
	if strings.HasPrefix(rest, "*") && !strings.ContainsAny(rest, " ,]}") {
		v, ok := p.anchors[rest[1:]]
		if !ok {
			return nil, fmt.Errorf("line %d: unknown alias %s", p.i+1, rest)
		}
		p.i++
		return v, nil
	}
	if strings.HasPrefix(rest, "&") {
		name, after, _ := strings.Cut(rest[1:], " ")
		v, err := p.parseValue(ind, strings.TrimSpace(after))
		if err != nil {
			return nil, err
		}
		if p.anchors == nil {
			p.anchors = map[string]any{}
		}
		p.anchors[name] = v
		return v, nil
	}
	switch {
	case rest == "":
		p.i++
		p.skip()
		if p.i < len(p.lines) {
			ni := indentOf(p.lines[p.i])
			if ni > ind || (ni == ind && isSeqItem(strings.TrimSpace(p.lines[p.i]))) {
				return p.parseBlock(ni)
			}
		}
		return nil, nil
	case strings.HasPrefix(rest, "|") || strings.HasPrefix(rest, ">"):
		p.i++
		var body []string
		for p.i < len(p.lines) {
			ln := p.lines[p.i]
			if strings.TrimSpace(ln) != "" && indentOf(ln) <= ind {
				break
			}
			body = append(body, strings.TrimLeft(ln, " "))
			p.i++
		}
		return strings.Join(body, "\n"), nil
	case strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "["):
		text := rest
		for !flowBalanced(text) {
			p.i++
			if p.i >= len(p.lines) {
				return nil, fmt.Errorf("unterminated flow collection %q", rest)
			}
			text += " " + stripComment(strings.TrimSpace(p.lines[p.i]))
		}
		p.i++
		v, n, err := parseFlow(text, 0)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(text[n:]) != "" {
			return nil, fmt.Errorf("trailing content after flow collection: %q", text[n:])
		}
		return v, nil
	default:
		p.i++
		return scalar(rest), nil
	}
}

func (p *yamlParser) parseSeq(ind int) ([]any, error) {
	var out []any
	for {
		p.skip()
		if p.i >= len(p.lines) {
			return out, nil
		}
		ln := p.lines[p.i]
		t := strings.TrimSpace(ln)
		if indentOf(ln) != ind || !isSeqItem(t) {
			if indentOf(ln) > ind {
				return nil, fmt.Errorf("line %d: unexpected indent in sequence: %q", p.i+1, t)
			}
			return out, nil
		}
		content := strings.TrimSpace(strings.TrimPrefix(t, "-"))
		if content == "" {
			v, err := p.parseValue(ind, "")
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		if c := content[0]; c != '{' && c != '[' && c != '"' && c != '\'' {
			if _, _, ok := splitKey(content); ok {
				// `- key: value` starts a mapping whose keys sit two columns in.
				p.lines[p.i] = strings.Repeat(" ", ind+2) + content
				v, err := p.parseMap(ind + 2)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
				continue
			}
		}
		v, err := p.parseValue(ind, content)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

// splitKey splits `key: rest` (or `key:`) at the first colon outside quotes and brackets.
func splitKey(t string) (string, string, bool) {
	depth, q := 0, byte(0)
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case q != 0:
			if q == '"' && c == '\\' {
				i++ // an escaped character inside a double-quoted string
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
		case c == ':' && depth == 0 && (i+1 == len(t) || t[i+1] == ' '):
			return unquote(strings.TrimSpace(t[:i])), strings.TrimSpace(t[i+1:]), true
		}
	}
	return "", "", false
}

// stripComment drops a trailing ` # comment` outside quotes.
func stripComment(s string) string {
	q := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if q == '"' && c == '\\' {
				i++ // an escaped character inside a double-quoted string
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

func flowBalanced(s string) bool {
	depth, q := 0, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if q == '"' && c == '\\' {
				i++ // an escaped character inside a double-quoted string
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
		}
	}
	return depth == 0
}

// parseFlow parses a flow value starting at s[i]; it returns the value and the index after it.
func parseFlow(s string, i int) (any, int, error) {
	for i < len(s) && s[i] == ' ' {
		i++
	}
	if i >= len(s) {
		return nil, i, fmt.Errorf("empty flow value")
	}
	switch s[i] {
	case '{':
		m := map[string]any{}
		i++
		for {
			for i < len(s) && (s[i] == ' ' || s[i] == ',') {
				i++
			}
			if i >= len(s) {
				return nil, i, fmt.Errorf("unterminated flow mapping")
			}
			if s[i] == '}' {
				return m, i + 1, nil
			}
			ks, ke := i, flowScalarEnd(s, i, true)
			key := unquote(strings.TrimSpace(s[ks:ke]))
			i = ke
			if i >= len(s) || s[i] != ':' {
				return nil, i, fmt.Errorf("flow mapping key %q without a value", key)
			}
			v, n, err := parseFlow(s, i+1)
			if err != nil {
				return nil, n, err
			}
			m[key] = v
			i = n
		}
	case '[':
		var out []any
		i++
		for {
			for i < len(s) && (s[i] == ' ' || s[i] == ',') {
				i++
			}
			if i >= len(s) {
				return nil, i, fmt.Errorf("unterminated flow sequence")
			}
			if s[i] == ']' {
				return out, i + 1, nil
			}
			v, n, err := parseFlow(s, i)
			if err != nil {
				return nil, n, err
			}
			out = append(out, v)
			i = n
		}
	default:
		e := flowScalarEnd(s, i, false)
		return scalar(strings.TrimSpace(s[i:e])), e, nil
	}
}

// flowScalarEnd finds where a flow scalar ends: a `,`, `}` or `]` (or, for a key, `: `) outside quotes.
func flowScalarEnd(s string, i int, key bool) int {
	q := byte(0)
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if q == '"' && c == '\\' {
				i++ // an escaped character inside a double-quoted string
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == ',' || c == '}' || c == ']':
			return i
		case key && c == ':' && (i+1 == len(s) || s[i+1] == ' '):
			return i
		}
	}
	return i
}

func scalar(s string) any {
	if s == "" || s == "~" || s == "null" {
		return nil
	}
	return unquote(s)
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}
