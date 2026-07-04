package orchestrator

import (
	"fmt"
	"strings"
	"unicode"
)

type Target struct {
	Hostname string
	IP       string
	Platform string
	Labels   map[string]string
}

type Selector func(Target) bool

type selectorParser struct {
	tokens []string
	pos    int
}

func CompileSelector(input string) (Selector, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	tokens, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	p := &selectorParser{tokens: tokens}
	selector, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(tokens) {
		return nil, fmt.Errorf("unexpected selector token %q", tokens[p.pos])
	}
	return selector, nil
}

func tokenize(input string) ([]string, error) {
	var tokens []string
	for i := 0; i < len(input); {
		if unicode.IsSpace(rune(input[i])) {
			i++
			continue
		}
		if strings.ContainsRune("()=", rune(input[i])) {
			tokens = append(tokens, string(input[i]))
			i++
			continue
		}
		if input[i] == '!' && i+1 < len(input) && input[i+1] == '=' {
			tokens = append(tokens, "!=")
			i += 2
			continue
		}
		if input[i] == '!' {
			tokens = append(tokens, "not")
			i++
			continue
		}
		if input[i] == '\'' || input[i] == '"' {
			quote := input[i]
			i++
			start := i
			for i < len(input) && input[i] != quote {
				i++
			}
			if i == len(input) {
				return nil, fmt.Errorf("unterminated quoted selector value")
			}
			tokens = append(tokens, input[start:i])
			i++
			continue
		}
		start := i
		for i < len(input) && !unicode.IsSpace(rune(input[i])) && !strings.ContainsRune("()=!", rune(input[i])) {
			i++
		}
		tokens = append(tokens, input[start:i])
	}
	return tokens, nil
}

func (p *selectorParser) accept(value string) bool {
	if p.pos < len(p.tokens) && strings.EqualFold(p.tokens[p.pos], value) {
		p.pos++
		return true
	}
	return false
}

func (p *selectorParser) parseOr() (Selector, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		previous := left
		left = func(target Target) bool { return previous(target) || right(target) }
	}
	return left, nil
}

func (p *selectorParser) parseAnd() (Selector, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.accept("and") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		previous := left
		left = func(target Target) bool { return previous(target) && right(target) }
	}
	return left, nil
}

func (p *selectorParser) parseUnary() (Selector, error) {
	if p.accept("not") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return func(target Target) bool { return !inner(target) }, nil
	}
	if p.accept("(") {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.accept(")") {
			return nil, fmt.Errorf("selector is missing closing parenthesis")
		}
		return inner, nil
	}
	return p.parsePredicate()
}

func (p *selectorParser) parsePredicate() (Selector, error) {
	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("expected selector predicate")
	}
	key := strings.ToLower(p.tokens[p.pos])
	p.pos++
	if p.pos >= len(p.tokens) || p.tokens[p.pos] != "=" && p.tokens[p.pos] != "!=" {
		return nil, fmt.Errorf("selector key %q must use = or !=", key)
	}
	op := p.tokens[p.pos]
	p.pos++
	if p.pos >= len(p.tokens) || p.tokens[p.pos] == "(" || p.tokens[p.pos] == ")" {
		return nil, fmt.Errorf("selector key %q is missing a value", key)
	}
	value := p.tokens[p.pos]
	p.pos++
	return func(target Target) bool {
		actual, exists := targetValue(target, key)
		matched := exists && strings.EqualFold(actual, value)
		if op == "!=" {
			return !matched
		}
		return matched
	}, nil
}

func targetValue(target Target, key string) (string, bool) {
	switch key {
	case "name", "hostname":
		return target.Hostname, strings.TrimSpace(target.Hostname) != ""
	case "ip", "address":
		return target.IP, strings.TrimSpace(target.IP) != ""
	case "type", "platform":
		return target.Platform, strings.TrimSpace(target.Platform) != ""
	}
	for label, value := range target.Labels {
		if strings.EqualFold(label, key) {
			return value, true
		}
	}
	return "", false
}
