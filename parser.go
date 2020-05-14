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
	// Decode and replace all occurrences of hexadecimal content.
	var errpanic error
	defer func() {
		r := recover()
		if r != nil {
			errpanic = fmt.Errorf("recovered from panic: %v", r)
		}
	}()
	b := hexRE.ReplaceAllStringFunc(content,
		func(h string) string {
			r, err := hex.DecodeString(strings.Replace(strings.Trim(h, "|"), " ", "", -1))
			if err != nil {
				panic("invalid hexRE regexp")
			}
			return string(r)
		})
	return []byte(b), errpanic
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

// parseLenMatch parses a LenMatch (like urilen).
func parseLenMatch(k lenMatchType, s string) (*LenMatch, error) {
	m := new(LenMatch)
	m.Kind = k
	switch {
	// Simple case, no operators.
	case !strings.ContainsAny(s, "><"):
		// Ignore options after ','.
		numTmp := strings.Split(s, ",")[0]
		num, err := strconv.Atoi(strings.TrimSpace(numTmp))
		if err != nil {
			return nil, fmt.Errorf("%v is not an integer", s)
		}
		m.Num = num

	// Leading operator, single number.
	case strings.HasPrefix(s, ">") || strings.HasPrefix(s, "<"):
		m.Operator = s[0:1]
		// Strip leading < or >.
		numTmp := strings.TrimLeft(s, "><")
		// Ignore options after ','.
		numTmp = strings.Split(numTmp, ",")[0]
		num, err := strconv.Atoi(strings.TrimSpace(numTmp))
		if err != nil {
			return nil, fmt.Errorf("%v is not an integer", s)
		}
		m.Num = num

	// Min/Max center operator.
	case strings.Contains(s, "<>"):
		m.Operator = "<>"
		parts := strings.Split(s, "<>")
		if len(parts) != 2 {
			return nil, fmt.Errorf("must have exactly 2 parts for min/max operator. got %d", len(parts))
		}
		var min, max int
		var err error
		min, err = strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("%v is not an integer", strings.TrimSpace(parts[0]))
		}
		maxTmp := strings.Split(parts[1], ",")[0]
		max, err = strconv.Atoi(strings.TrimSpace(maxTmp))
		if err != nil {
			return nil, fmt.Errorf("%v is not an integer", strings.TrimSpace(maxTmp))
		}
		// Do stuff to handle options here.
		m.Min = min
		m.Max = max
	}

	// Parse options:
	if strings.Contains(s, ",") {
		opts := strings.Split(s, ",")[1:]
		for i, o := range opts {
			opts[i] = strings.TrimSpace(o)
		}
		m.Options = opts
	}
	return m, nil
}

func parseBase64Decode(k byteMatchType, s string) (*ByteMatch, error) {
	if k != b64Decode {
		return nil, fmt.Errorf("kind %v is not base64_decode", k)
	}
	b := new(ByteMatch)
	b.Kind = k

	// All options to base64_decode are optional, and specified by their keyword.
	for _, p := range strings.Split(s, ",") {
		v := strings.TrimSpace(p)
		switch {
		case strings.HasPrefix(v, "bytes"):
			b.NumBytes = strings.TrimSpace(strings.SplitAfter(v, "bytes")[1])
		case strings.HasPrefix(v, "offset"):
			val := strings.TrimSpace(strings.SplitAfter(v, "offset")[1])
			i, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("offset is not an int: %s; %s", val, err)
			}
			if i < 1 {
				return nil, fmt.Errorf("offset must be positive, non-zero values only")
			}
			b.Offset = i
		case strings.HasPrefix(v, "relative"):
			b.Options = []string{"relative"}
		}
	}
	return b, nil
}

// parseByteMatch parses a ByteMatch.
func parseByteMatch(k byteMatchType, s string) (*ByteMatch, error) {
	b := new(ByteMatch)
	b.Kind = k

	parts := strings.Split(s, ",")

	// Num bytes is required for all byteMatchType keywords.
	if len(parts) < 1 {
		return nil, fmt.Errorf("%s keyword has %d parts", s, len(parts))
	}

	b.NumBytes = strings.TrimSpace(parts[0])

	if len(parts) < b.Kind.minLen() {
		return nil, fmt.Errorf("invalid %s length: %d", b.Kind, len(parts))
	}

	if k == bExtract || k == bJump {
		// Parse offset.
		offset, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("%s offset is not an int: %v; %s", b.Kind, parts[1], err)
		}
		b.Offset = offset
	}

	if k == bExtract {
		// Parse variable name.
		name := parts[2]
		b.Variable = name
	}

	if k == bTest {
		// Parse operator.
		b.Operator = strings.TrimSpace(parts[1])
		// Parse value. Can use a variable.
		b.Value = strings.TrimSpace(parts[2])
		// Parse offset.
		offset, err := strconv.Atoi(strings.TrimSpace(parts[3]))
		if err != nil {
			return nil, fmt.Errorf("%s offset is not an int: %v; %s", b.Kind, parts[1], err)
		}
		b.Offset = offset
	}

	// The rest of the options, for all types not b64decode
	for i, l := b.Kind.minLen(), len(parts); i < l; i++ {
		parts[i] = strings.TrimSpace(parts[i])
		b.Options = append(b.Options, parts[i])
	}

	return b, nil
}

// parseFlowbit parses a flowbit.
func parseFlowbit(s string) (*Flowbit, error) {
	parts := strings.Split(s, ",")
	if len(parts) < 1 {
		return nil, fmt.Errorf("couldn't parse flowbit string: %s", s)
	}
	// Ensure all actions are of valid type.
	a := strings.TrimSpace(parts[0])
	if !inSlice(a, []string{"noalert", "isset", "isnotset", "set", "unset", "toggle"}) {
		return nil, fmt.Errorf("invalid action for flowbit: %s", a)
	}
	fb := &Flowbit{
		Action: a,
	}
	if fb.Action == "noalert" && len(parts) > 1 {
		return nil, fmt.Errorf("noalert shouldn't have a value")
	}
	if len(parts) == 2 {
		fb.Value = strings.TrimSpace(parts[1])
	}
	return fb, nil
}

// parseXbit parses an xbit.
func parseXbit(s string) (*Xbit, error) {
	parts := strings.Split(s, ",")
	// All xbits must have an action, name and track
	if len(parts) < 3 {
		return nil, fmt.Errorf("not enough parts for xbits: %s", s)
	}
	// Ensure all actions are of valid type.
	a := strings.TrimSpace(parts[0])
	if !inSlice(a, []string{"set", "unset", "isset", "isnotset", "toggle"}) {
		return nil, fmt.Errorf("invalid action for xbits: %s", a)
	}
	xb := &Xbit{
		Action: a,
		Name:   strings.TrimSpace(parts[1]),
	}

	// Track.
	t := strings.Fields(parts[2])
	if len(t) != 2 {
		return nil, fmt.Errorf("wrong number of parts for track: %v", t)
	}
	if t[0] != "track" {
		return nil, fmt.Errorf("%s should be 'track'", t[0])
	}
	xb.Track = t[1]

	// Expire
	if len(parts) == 4 {
		e := strings.Fields(parts[3])
		if len(e) != 2 {
			return nil, fmt.Errorf("wrong number of parts for expire: %v", e)
		}
		if e[0] != "expire" {
			return nil, fmt.Errorf("%s should be 'expire'", e[0])
		}
		xb.Expire = e[1]
	}
	return xb, nil

}

// parseFlowint parses a flowint.
func parseFlowint(s string) (*Flowint, error) {
	parts := strings.Split(s, ",")
	// All flowints must have a name and modifier
	if len(parts) < 2 {
		return nil, fmt.Errorf("not enough parts for flowint: %s", s)
	}
	// Ensure all actions are of valid type.
	m := strings.TrimSpace(parts[1])
	if !inSlice(m, []string{"+", "-", "=", ">", "<", ">=", "<=", "==", "!=", "isset", "isnotset"}) {
		return nil, fmt.Errorf("invalid modifier for flowint: %s", m)
	}
	fi := &Flowint{
		Name:     strings.TrimSpace(parts[0]),
		Modifier: m,
	}

	if len(parts) == 3 {
		fi.Value = strings.TrimSpace(parts[2])
	}

	return fi, nil
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
	if r.Disabled {
		// ignoring comment for rule with empty action
		return nil
	}
	rule, err := parseRuleAux(key.value, true)

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

// network decodes an IDS rule network (networks and ports) based on its key.
func (r *Rule) network(key item, l *lexer) error {
	items := strings.Split(strings.Trim(key.value, "[]"), ",")
	// Validate that no items contain spaces.
	for _, i := range items {
		if len(strings.Fields(i)) > 1 || len(strings.TrimSpace(i)) != len(i) {
			return fmt.Errorf("network component contains spaces: %v", i)
		}
	}
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
	// TODO: Many of these simple tags could be factored into nicer structures.
	case inSlice(key.value, []string{"classtype", "flow", "tag", "priority", "app-layer-protocol", "noalert",
		"flags", "ipopts", "ip_proto", "geoip", "fragbits", "fragoffset", "tos",
		"window",
		"threshold", "detection_filter",
		"dce_iface", "dce_opnum", "dce_stub_data",
		"asn1"}):
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return fmt.Errorf("no valid value for %s tag", key.value)
		}
		if r.Tags == nil {
			r.Tags = make(map[string]string)
		}
		r.Tags[key.value] = nextItem.value
	case inSlice(key.value, []string{"sameip", "tls.store", "ftpbounce"}):
		r.Statements = append(r.Statements, key.value)
	case inSlice(key.value, tlsTags):
		t := &TLSTag{
			Key: key.value,
		}
		nextItem := l.nextItem()
		if nextItem.typ == itemNot {
			t.Negate = true
			nextItem = l.nextItem()
		}
		t.Value = nextItem.value
		r.TLSTags = append(r.TLSTags, t)
	case key.value == "stream_size":
		nextItem := l.nextItem()
		parts := strings.Split(nextItem.value, ",")
		if len(parts) != 3 {
			return fmt.Errorf("invalid number of parts for stream_size: %d", len(parts))
		}
		num, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil {
			return fmt.Errorf("comparison number is not an integer: %v", parts[2])
		}
		r.StreamMatch = &StreamCmp{
			Direction: parts[0],
			Operator:  parts[1],
			Number:    num,
		}
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
		var d DataPos
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
			con := &Content{
				DataPosition: dataPosition,
				Pattern:      c,
				Negate:       negate,
				Options:      options,
			}
			r.Matchers = append(r.Matchers, con)
		} else {
			return fmt.Errorf("invalid type %q for option content", nextItem.typ)
		}
	case inSlice(key.value, []string{"http_cookie", "http_raw_cookie", "http_method", "http_header", "http_raw_header",
		"http_uri", "http_raw_uri", "http_user_agent", "http_stat_code", "http_stat_msg",
		"http_client_body", "http_server_body", "http_host", "nocase", "rawbytes", "startswith", "endswith"}):
		lastContent := r.LastContent()
		if lastContent == nil {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		lastContent.Options = append(lastContent.Options, &ContentOption{Name: key.value})
	case inSlice(key.value, []string{"depth", "distance", "offset", "within"}):
		lastContent := r.LastContent()
		if lastContent == nil {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return fmt.Errorf("no value for content option %s", key.value)
		}

		lastContent.Options = append(lastContent.Options, &ContentOption{Name: key.value, Value: nextItem.value})

	case key.value == "fast_pattern":
		lastContent := r.LastContent()
		if lastContent == nil {
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
			r.Matchers = append(r.Matchers, p)
		} else {
			return fmt.Errorf("invalid type %q for option content", nextItem.typ)
		}
	case inSlice(key.value, allbyteMatchTypeNames()):
		k, err := byteMatcher(key.value)
		if err != nil {
			return fmt.Errorf("%s is not a supported byteMatchType keyword", key.value)
		}

		// Handle negation logic here, don't want to pass lexer to parseByteMatch.
		nextItem := l.nextItem()
		var negate bool
		if k == isDataAt && nextItem.typ == itemNot {
			negate = true
			nextItem = l.nextItem()
		}

		var b *ByteMatch
		// Parse base64_decode differently as it has odd semantics.
		if k == b64Decode {
			b, err = parseBase64Decode(k, nextItem.value)
			if err != nil {
				return fmt.Errorf("could not parse base64Decode: %v", err)
			}
			// base64_decode allows NumBytes to be empty, an int or a variable.
			if i, err := strconv.Atoi(b.NumBytes); err != nil && b.NumBytes != "" {
				// NumBytes is not an int, check if it is a variable from byte_extract.
				if !r.HasVar(b.NumBytes) {
					return fmt.Errorf("number of bytes is not an int, or an extracted variable: %s; %s", b.NumBytes, err)
				} else if i < 1 {
					return fmt.Errorf("bytes must be positive, non-zero values only: %d", i)
				}
			}
		} else {
			b, err = parseByteMatch(k, nextItem.value)
			if err != nil {
				return fmt.Errorf("could not parse byteMatch: %v", err)
			}
			if _, err := strconv.Atoi(b.NumBytes); err != nil {
				// NumBytes is not an int, check if it is a variable from byte_extract.
				if !r.HasVar(b.NumBytes) {
					return fmt.Errorf("number of bytes is not an int, or an extracted variable: %s; %s", b.NumBytes, err)
				}
			}
		}
		b.Negate = negate

		r.Matchers = append(r.Matchers, b)
	case inSlice(key.value, allLenMatchTypeNames()):
		k, err := lenMatcher(key.value)
		if err != nil {
			return fmt.Errorf("%s is not a support lenMatch keyword", key.value)
		}
		nextItem := l.nextItem()
		m, err := parseLenMatch(k, nextItem.value)
		if err != nil {
			return fmt.Errorf("could not parse LenMatch: %v", err)
		}
		m.DataPosition = dataPosition
		r.Matchers = append(r.Matchers, m)
	case key.value == "flowbits":
		nextItem := l.nextItem()
		fb, err := parseFlowbit(nextItem.value)
		if err != nil {
			return fmt.Errorf("error parsing flowbit: %v", err)
		}
		r.Flowbits = append(r.Flowbits, fb)
	case key.value == "xbits":
		nextItem := l.nextItem()
		xb, err := parseXbit(nextItem.value)
		if err != nil {
			return fmt.Errorf("error parsing xbits: %v", err)
		}
		r.Xbits = append(r.Xbits, xb)
	case key.value == "flowint":
		nextItem := l.nextItem()
		fi, err := parseFlowint(nextItem.value)
		if err != nil {
			return fmt.Errorf("error parsing flowint: %v", err)
		}
		r.Flowints = append(r.Flowints, fi)
	default:
		return &UnsupportedOptionError{
			Options: []string{key.value},
		}
	}
	return nil
}

// UnsupportedOptionError contains a partially parsed rule, and the options that aren't
// supported for parsing.
type UnsupportedOptionError struct {
	Rule    *Rule
	Options []string
}

// Error returns a string for UnsupportedOptionError
func (uoe *UnsupportedOptionError) Error() string {
	return fmt.Sprintf("rule contains unsupported option(s): %s", strings.Join(uoe.Options, ","))
}

// parseRuleAux parses an IDS rule, optionally ignoring comments.
func parseRuleAux(rule string, commented bool) (*Rule, error) {
	l, err := lex(rule)
	if err != nil {
		return nil, err
	}
	defer l.close()
	dataPosition = pktData
	r := &Rule{}
	var unsupportedOptions = make([]string, 0, 3)
	for item := l.nextItem(); item.typ != itemEOR && item.typ != itemEOF && err == nil; item = l.nextItem() {
		switch item.typ {
		case itemComment:
			if r.Action != "" || commented {
				// Ignore comment ending rule.
				return r, nil
			}
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
			// We will continue to parse a rule with unsupported options.
			if uerr, ok := err.(*UnsupportedOptionError); ok {
				unsupportedOptions = append(unsupportedOptions, uerr.Options...)
				// This is ugly but allows the parsing to continue.
				err = nil
			}
		case itemError:
			err = errors.New(item.value)
		}
		// Unrecoverable parse error.
		if err != nil {
			return nil, err
		}
	}

	// If we encountered one or more unsupported keys, return an UnsupportedOptionError.
	if len(unsupportedOptions) > 0 {
		return nil, &UnsupportedOptionError{
			Rule:    r,
			Options: unsupportedOptions,
		}
	}

	return r, nil
}

// ParseRule parses an IDS rule and returns a struct describing the rule.
func ParseRule(rule string) (*Rule, error) {
	return parseRuleAux(rule, false)
}
