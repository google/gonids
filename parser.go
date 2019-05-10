/* Copyright 2016 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package gonids implements a basic parser of IDS rules.
//
// For now the parser is very basic and it only parses a subset of fields.
// We intentionally omit http_encode as it doesn't seem to be used in practice.
package gonids

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// hexRE matches on hexadecimal content like |41 41 41| for example.
var hexRE = regexp.MustCompile(`(?i)(\|(?:\s*[a-f0-9]{2}\s*)+\|)`)

// escapeRE matches char that needs to escaped in regexp.
var escapeRE = regexp.MustCompile(`([()+.'\\])`)

// metaSplitRE matches string in metadata
var metaSplitRE = regexp.MustCompile(`,\s*`)

// parseContent decodes rule content match. For now it only takes care of escaped and hex
// encoded content.
func parseContent(content string) ([]byte, error) {
	// Unescape, decode and replace all occurrences of hexadecimal content.
	b := hexRE.ReplaceAllStringFunc(strings.Replace(content, `\`, "", -1),
		func(h string) string {
			r, err := hex.DecodeString(strings.Replace(strings.Trim(h, "|"), " ", "", -1))
			if err != nil {
				panic("invalid hexRE regexp")
			}
			return string(r)
		})
	return []byte(b), nil
}

// parsePCRE parses the components of a PCRE. Returns PCRE struct.
func parsePCRE(s string) (*PCRE, error) {
	c := strings.Count(s, "/")
	if c < 2 {
		return nil, fmt.Errorf("all pcre patterns must contain at least 2 '/', found: %d", c)
	}

	l := strings.LastIndex(s, "/")
	if l < 0 {
		return nil, fmt.Errorf("couldn't find options in PCRE")
	}

	i := strings.Index(s, "/")
	if l < 0 {
		return nil, fmt.Errorf("couldn't find start of pattern")
	}

	return &PCRE{
		Pattern: []byte(s[i+1 : l]),
		Options: []byte(s[l+1:]),
	}, nil
}

func unquote(s string) string {
	if strings.IndexByte(s, '"') < 0 {
		return s
	}
	return strings.Replace(s, `\"`, `"`, -1)
}

func inSlice(str string, strings []string) bool {
	for _, k := range strings {
		if str == k {
			return true
		}
	}
	return false
}

// comment decodes a comment (commented rule, or just a comment.)
func (r *Rule) comment(key item, l *lexer) error {
	if key.typ != itemComment {
		panic("item is not a comment")
	}
	// Pop off all leading # and space, try to parse as rule
	rule, err := ParseRule(strings.TrimLeft(key.value, "# "))

	// If there was an error this means the comment is not a rule.
	if err != nil {
		return fmt.Errorf("this is not a rule: %s", err)
	}

	// We parsed a rule, this was a comment so set the rule to disabled.
	rule.Disabled = true

	// Overwrite the rule we're working on with the recently parsed, disabled rule.
	*r = *rule
	return nil
}

// action decodes an IDS rule option based on its key.
func (r *Rule) action(key item, l *lexer) error {
	if key.typ != itemAction {
		panic("item is not an action")
	}
	r.Action = key.value
	return nil
}

// protocol decodes an IDS rule protocol based on its key.
func (r *Rule) protocol(key item, l *lexer) error {
	if key.typ != itemProtocol {
		panic("item is not a protocol")
	}
	r.Protocol = key.value
	return nil
}

// netSplitRE matches the characters to split a list of networks [$HOME_NET, 192.168.1.1/32] for example.
var netSplitRE = regexp.MustCompile(`\s*,\s*`)

// network decodes an IDS rule network (networks and ports) based on its key.
func (r *Rule) network(key item, l *lexer) error {
	items := netSplitRE.Split(strings.Trim(key.value, "[]"), -1)
	switch key.typ {
	case itemSourceAddress:
		r.Source.Nets = append(r.Source.Nets, items...)
	case itemSourcePort:
		r.Source.Ports = append(r.Source.Ports, items...)
	case itemDestinationAddress:
		r.Destination.Nets = append(r.Destination.Nets, items...)
	case itemDestinationPort:
		r.Destination.Ports = append(r.Destination.Ports, items...)
	default:
		panic("item is not a network component")
	}
	return nil
}

// direction decodes an IDS rule direction based on its key.
func (r *Rule) direction(key item, l *lexer) error {
	if key.typ != itemDirection {
		panic("item is not a direction")
	}
	switch key.value {
	case "->":
		r.Bidirectional = false
	case "<>":
		r.Bidirectional = true
	default:
		return fmt.Errorf("invalid direction operator %q", key.value)
	}
	return nil
}

var dataPosition = pktData

// option decodes an IDS rule option based on its key.
func (r *Rule) option(key item, l *lexer) error {
	if key.typ != itemOptionKey {
		panic("item is not an option key")
	}
	switch {
	case inSlice(key.value, []string{"classtype", "flow", "threshold", "tag", "priority"}):
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return fmt.Errorf("no valid value for %s tag", key.value)
		}
		if r.Tags == nil {
			r.Tags = make(map[string]string)
		}
		r.Tags[key.value] = nextItem.value
	case key.value == "reference":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no valid value for reference")
		}
		refs := strings.SplitN(nextItem.value, ",", 2)
		if len(refs) != 2 {
			return fmt.Errorf("invalid reference definition: %s", refs)
		}
		r.References = append(r.References, &Reference{Type: refs[0], Value: refs[1]})
	case key.value == "metadata":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no valid value for metadata")
		}
		metas := metaSplitRE.Split(nextItem.value, -1)
		for _, kv := range metas {
			metaTmp := strings.SplitN(kv, " ", 2)
			if len(metaTmp) != 2 {
				return fmt.Errorf("invalid metadata definition: %s", metaTmp)
			}
			r.Metas = append(r.Metas, &Metadata{Key: strings.TrimSpace(metaTmp[0]), Value: strings.TrimSpace(metaTmp[1])})
		}
	case key.value == "sid":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no value for option sid")
		}
		sid, err := strconv.Atoi(nextItem.value)
		if err != nil {
			return fmt.Errorf("invalid sid %s", nextItem.value)
		}
		r.SID = sid
	case key.value == "rev":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no value for option rev")
		}
		rev, err := strconv.Atoi(nextItem.value)
		if err != nil {
			return fmt.Errorf("invalid rev %s", nextItem.value)
		}
		r.Revision = rev
	case key.value == "msg":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValueString {
			return errors.New("no value for option msg")
		}
		r.Description = nextItem.value
	case isStickyBuffer(key.value):
		var d dataPos
		var err error
		if d, err = StickyBuffer(key.value); err != nil {
			return err
		}
		dataPosition = d
	case inSlice(key.value, []string{"content", "uricontent"}):
		nextItem := l.nextItem()
		negate := false
		if nextItem.typ == itemNot {
			nextItem = l.nextItem()
			negate = true
		}
		if nextItem.typ == itemOptionValueString {
			c, err := parseContent(nextItem.value)
			if err != nil {
				return err
			}
			var options []*ContentOption
			if key.value == "uricontent" {
				options = append(options, &ContentOption{Name: "http_uri"})
			}
			r.Contents = append(r.Contents, &Content{
				DataPosition: dataPosition,
				Pattern:      c,
				Negate:       negate,
				Options:      options,
			})
		} else {
			return fmt.Errorf("invalid type %q for option content", nextItem.typ)
		}
	case inSlice(key.value, []string{"http_cookie", "http_raw_cookie", "http_method", "http_header", "http_raw_header",
		"http_uri", "http_raw_uri", "http_user_agent", "http_stat_code", "http_stat_msg",
		"http_client_body", "http_server_body", "nocase"}):
		if len(r.Contents) == 0 {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		lastContent := r.Contents[len(r.Contents)-1]
		lastContent.Options = append(lastContent.Options, &ContentOption{Name: key.value})
	case inSlice(key.value, []string{"depth", "distance", "offset", "within"}):
		if len(r.Contents) == 0 {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return fmt.Errorf("no value for content option %s", key.value)
		}

		// check if the value is an integer value
		if _, err := strconv.Atoi(nextItem.value); err != nil {
			// check if it is the name of a var
			if _, ok := r.Vars[nextItem.value]; !ok {
				return fmt.Errorf("invalid value %s for option %s", nextItem.value, key.value)
			}
		}
		lastContent := r.Contents[len(r.Contents)-1]
		lastContent.Options = append(lastContent.Options, &ContentOption{Name: key.value, Value: nextItem.value})

	case key.value == "fast_pattern":
		if len(r.Contents) == 0 {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		var (
			only   bool
			offset int
			length int
		)
		nextItem := l.nextItem()
		if nextItem.typ == itemOptionValue {
			v := nextItem.value
			switch {
			case v == "only":
				only = true
			case strings.Contains(v, ","):
				s := strings.Split(v, ",")
				i, err := strconv.Atoi(s[0])
				if err != nil {
					return fmt.Errorf("fast_pattern offset is not an int: %s; %s", s[0], err)
				}
				offset = i
				i, err = strconv.Atoi(s[1])
				if err != nil {
					return fmt.Errorf("fast_pattern length is not an int: %s; %s", s[1], err)
				}
				length = i
			}
		}
		lastContent := r.Contents[len(r.Contents)-1]
		lastContent.FastPattern = FastPattern{true, only, offset, length}
	case key.value == "pcre":
		nextItem := l.nextItem()
		negate := false
		if nextItem.typ == itemNot {
			nextItem = l.nextItem()
			negate = true
		}
		if nextItem.typ == itemOptionValueString {
			p, err := parsePCRE(unquote(nextItem.value))
			if err != nil {
				return err
			}
			p.Negate = negate
			r.PCREs = append(r.PCREs, p)
		} else {
			return fmt.Errorf("invalid type %q for option content", nextItem.typ)
		}
	case key.value == "byte_extract":
		if len(r.Contents) == 0 {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		nextItem := l.nextItem()
		parts := strings.Split(nextItem.value, ",")
		if len(parts) < 3 {
			return fmt.Errorf("invalid byte_extract value: %s", nextItem.value)
		}

		v := new(Var)

		n, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("byte_extract number of bytes is not an int: %s; %s", parts[0], err)
		}
		v.NumBytes = n

		offset, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("byte_extract offset is not an int: %s; %s", parts[1], err)
		}
		v.Offset = offset

		name := parts[2]
		if r.Vars == nil {
			// Lazy init r.Vars if necessary
			r.Vars = make(map[string]*Var)
		} else if _, exists := r.Vars[name]; exists {
			return fmt.Errorf("byte_extract var already declared: %s", name)
		}

		// options
		for i, l := 3, len(parts); i < l; i++ {
			parts[i] = strings.TrimSpace(parts[i])
			v.Options = append(v.Options, parts[i])
		}

		r.Vars[name] = v
		lastContent := r.Contents[len(r.Contents)-1]
		lastContent.Options = append(lastContent.Options, &ContentOption{Name: key.value, Value: strings.Join(parts, ",")})
	}
	return nil
}

// ParseRule parses an IDS rule and returns a struct describing the rule.
func ParseRule(rule string) (*Rule, error) {
	l, err := lex(rule)
	if err != nil {
		return nil, err
	}
	dataPosition = pktData
	r := &Rule{}
	for item := l.nextItem(); item.typ != itemEOR && item.typ != itemEOF && err == nil; item = l.nextItem() {
		switch item.typ {
		case itemComment:
			err = r.comment(item, l)
			// Error here means that the comment was not a commented rule.
			// So we're not parsing a rule and we need to break out.
			if err != nil {
				break
			}
			// This line was a commented rule.
			return r, nil
		case itemAction:
			err = r.action(item, l)
		case itemProtocol:
			err = r.protocol(item, l)
		case itemSourceAddress, itemDestinationAddress, itemSourcePort, itemDestinationPort:
			err = r.network(item, l)
		case itemDirection:
			err = r.direction(item, l)
		case itemOptionKey:
			err = r.option(item, l)
		case itemError:
			err = errors.New(item.value)
		}
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}
