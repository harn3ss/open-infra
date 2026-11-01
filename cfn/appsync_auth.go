package cfn

import (
	"regexp"
	"strings"
)

// AppSync auth. On AWS every field of an API is protected: a field with no auth directive uses the
// API's default AuthenticationType, and there is no unauthenticated mode. open-appsync enforces the
// @aws_* directives a schema carries and treats a field with none (on itself or its type) as public. So
// a template whose schema leans on the default mode would deploy with open fields. The translator
// refuses it unless every root operation field (Query, Mutation, Subscription — the only way into the
// graph) carries a directive, on the field or on its type.

var (
	sdlSchemaBlockRE = regexp.MustCompile(`\bschema\b[^{]*\{([^}]*)\}`)
	sdlRootOpRE      = regexp.MustCompile(`\b(query|mutation|subscription)\s*:\s*([_A-Za-z][_0-9A-Za-z]*)`)
	sdlTypeRE        = regexp.MustCompile(`\b(?:extend\s+)?type\s+([_A-Za-z][_0-9A-Za-z]*)([^{]*)\{`)
	sdlFieldStartRE  = regexp.MustCompile(`^([_A-Za-z][_0-9A-Za-z]*)\s*[(:]`)
)

// defaultAuthDirective is the schema directive that enforces an AppSync AuthenticationType.
var defaultAuthDirective = map[string]string{
	"API_KEY": "@aws_api_key", "AWS_IAM": "@aws_iam", "AMAZON_COGNITO_USER_POOLS": "@aws_cognito_user_pools",
	"OPENID_CONNECT": "@aws_oidc", "AWS_LAMBDA": "@aws_lambda",
}

// rootFieldsWithoutAuth returns "Type.field" for each root operation field with no @aws_* directive on
// itself or its type. ok=false when the SDL could not be scanned (unbalanced braces/parentheses): the
// caller then treats the schema as unprotected.
func rootFieldsWithoutAuth(sdl string) (missing []string, ok bool) {
	src := stripSDLNoise(sdl)
	roots := map[string]bool{"Query": true, "Mutation": true, "Subscription": true}
	if m := sdlSchemaBlockRE.FindStringSubmatch(src); m != nil {
		roots = map[string]bool{}
		for _, op := range sdlRootOpRE.FindAllStringSubmatch(m[1], -1) {
			roots[op[2]] = true
		}
	}
	for _, loc := range sdlTypeRE.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		if !roots[name] {
			continue
		}
		typeAuth := strings.Contains(src[loc[4]:loc[5]], "@aws_")
		body, end := braceBody(src, loc[1]-1)
		if end < 0 {
			return nil, false
		}
		fields, fok := sdlFields(body)
		if !fok {
			return nil, false
		}
		for _, f := range fields {
			if !typeAuth && !strings.Contains(f.text, "@aws_") {
				missing = append(missing, name+"."+f.name)
			}
		}
	}
	return missing, true
}

type sdlField struct{ name, text string }

// sdlFields splits a type body into field definitions. A field starts with `name(` or `name:` at
// parenthesis depth 0; anything after it (arguments, the type, directives on later lines) belongs to it.
func sdlFields(body string) ([]sdlField, bool) {
	var out []sdlField
	depth := 0
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if depth == 0 {
			if m := sdlFieldStartRE.FindStringSubmatch(t); m != nil {
				out = append(out, sdlField{name: m[1], text: t})
			} else if len(out) > 0 {
				out[len(out)-1].text += " " + t
			}
		} else if len(out) > 0 {
			out[len(out)-1].text += " " + t
		}
		depth += strings.Count(t, "(") - strings.Count(t, ")")
		if depth < 0 {
			return nil, false
		}
	}
	return out, depth == 0
}

// braceBody returns the text between the '{' at open and its matching '}', and the index of that '}'
// (-1 when unbalanced).
func braceBody(s string, open int) (string, int) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[open+1 : i], i
			}
		}
	}
	return "", -1
}

// stripSDLNoise removes comments and string literals (descriptions), which may contain braces or
// directive-like text.
func stripSDLNoise(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case strings.HasPrefix(s[i:], `"""`):
			if j := strings.Index(s[i+3:], `"""`); j >= 0 {
				i += j + 5
				continue
			}
			return b.String()
		case s[i] == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' && s[j] != '\n' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			i = j
			continue
		case s[i] == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
