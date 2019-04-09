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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Rule describes an IDS rule.
type Rule struct {
	// Disbled identifies if the rule is disabled/commented out.
	Disabled bool
	// Action is the action the rule will take (alert, pass, drop, etc.).
	Action string
	// Protocol is the protocol the rule looks at.
	Protocol string
	// Source is the address and ports for the source of the traffic.
	Source Network
	// Destination is the address and ports for the source of the traffic.
	Destination Network
	// Bidirectional indicates the directionality of a rule (-> or <>).
	Bidirectional bool
	// SID is the identifier of the rule.
	SID int
	// Revision is the revision of the rule.
	Revision int
	// Description is the msg field of the rule.
	Description string
	// References contains references associated to the rule (e.g. CVE number).
	References []*Reference
	// TODO: Define some structure for tracking checks that do not directly apply
	// to a content. urilen, dsize, etc. Various buffers, and directions need structured
	// places to live.
	// Contents are all the decoded content matches.
	Contents []*Content
	// PCREs is a slice of PCRE structs that represent the regular expressions in a rule
	PCREs []*PCRE
	// Tags is a map of tag names to tag values (e.g. classtype:trojan).
	Tags map[string]string
	//Metas is a slice of Metadata 
	Metas  []*Metadata
}

// TODO: Ensure all values either begin with $ (variable) or they are valid IPNet/int.

//Metadata describes metadata tags in key-value struct
type Metadata struct{
	Key 	string 
	Value	string
}

// Network describes the IP addresses and port numbers used in a rule.
type Network struct {
	Nets  []string // Currently just []string because these can be variables $HOME_NET, not a valid IPNet.
	Ports []string // Currently just []string because these can be variables $HTTP_PORTS, not just ints.
}

type dataPos int

const (
	pktData dataPos = iota
	fileData
	base64Data
)

// Content describes a rule content. A content is composed of a pattern followed by options.
type Content struct {
	// DataPosition defaults to pkt_data state, can be modified to apply to file_data, base64_data locations.
	// This value will apply to all following contents, to reset to default you must reset DataPosition during processing.
	DataPosition dataPos
	// FastPattern settings for the content.
	FastPattern FastPattern
	// Pattern is the pattern match of a content (e.g. HTTP in content:"HTTP").
	Pattern []byte
	// Negate is true for negated content match.
	Negate bool
	// Options are the option associated to the content (e.g. http_header).
	Options []*ContentOption
}

// PCRE describes a PCRE item of a rule.
type PCRE struct {
	Pattern []byte
	Negate bool
	Options []byte
}

// FastPattern describes various properties of a fast_pattern value for a content.
type FastPattern struct {
	Enabled bool
	Only    bool
	Offset  int
	Length  int
}

// ContentOption describes an option set on a rule content.
type ContentOption struct {
	// Name is the name of the option (e.g. offset).
	Name string
	// Value is the value associated to the option, default to 0 for option without value.
	Value int
}

// Reference describes a gonids reference in a rule.
type Reference struct {
	// Type is the system name for the reference: (url, cve, md5, etc.)
	Type string
	// Value is the identifier in the system: (address, cvd-id, hash)
	Value string
}

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

	i := strings.Index(s,"/")
	if l < 0 {
		return nil, fmt.Errorf("couldn't find start of pattern")
	}

	return &PCRE{
		Pattern: []byte(s[i+1:l]),
		Options: []byte(s[l+1:]),
	}, nil
}

// escape escapes special char used in regexp.
func escape(r string) string {
	return escapeRE.ReplaceAllString(r, `\$1`)
}

// within returns the within value for a specific content.
func within(options []*ContentOption) int {
	for _, o := range options {
		if o.Name == "within" {
			return int(o.Value)
		}
	}
	return 0
}

// RE returns all content matches as a single and simple regexp.
func (r *Rule) RE() string {
	var re string
	for _, c := range r.Contents {
		// TODO: handle pcre, depth, offset, distance.
		if w := within(c.Options); w != 0 {
			re += fmt.Sprintf(".{0,%d}", w)
		} else {
			re += ".*"
		}
		re += escape(string(c.Pattern))
	}
	return re
}

// CVE extracts CVE from a rule.
func (r *Rule) CVE() string {
	for _, ref := range r.References {
		if ref.Type == "cve" {
			return ref.Value
		}
	}
	return ""
}

// TODO: Add a String method for Content to add negation, and options.

// ToRegexp returns a string that can be used as a regular expression
// to identify content matches in an ASCII dump of a packet capture (tcpdump -A).
func (c *Content) ToRegexp() string {
	var buffer bytes.Buffer
	for _, b := range c.Pattern {
		if b > 126 || b < 32 {
			buffer.WriteString(".")
		} else {
			buffer.WriteByte(b)
		}
	}
	return regexp.QuoteMeta(buffer.String())
}

// FormatPattern returns a string for a Pattern in a content
func (c *Content) FormatPattern() string {
	var buffer bytes.Buffer
	pipe := false
	for _, b := range c.Pattern {
		if b != ' ' && (b > 126 || b < 35 || b == ':' || b == ';') {
			if !pipe {
				buffer.WriteByte('|')
				pipe = true
			} else {
				buffer.WriteString(" ")
			}
			buffer.WriteString(fmt.Sprintf("%.2X", b))
		} else {
			if pipe {
				buffer.WriteByte('|')
				pipe = false
			}
			buffer.WriteByte(b)
		}
	}
	if pipe {
		buffer.WriteByte('|')
	}
	return buffer.String()
}

// comment decodes a comment (commented rule, or just a comment.)
func (r *Rule) comment(key item, l *lexer) error {
	if key.typ != itemComment {
		panic ("item is not a comment")
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
	switch key.value {
	case "classtype", "flow", "threshold", "tag", "priority":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return fmt.Errorf("no valid value for %s tag", key.value)
		}
		if r.Tags == nil {
			r.Tags = make(map[string]string)
		}
		r.Tags[key.value] = nextItem.value
	case "reference":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no valid value for reference")
		}
		refs := strings.SplitN(nextItem.value, ",", 2)
		if len(refs) != 2 {
			return fmt.Errorf("invalid reference definition: %s", refs)
		}
		r.References = append(r.References, &Reference{Type: refs[0], Value: refs[1]})
	case "metadata":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no valid value for metadata")
		}
		metas := metaSplitRE.Split(nextItem.value, -1)
		for _,kv := range metas{
			metaTmp := strings.SplitN(kv, " ", 2)
			if len(metaTmp) != 2 {
				return fmt.Errorf("invalid metadata definition: %s", metaTmp)
			}
			r.Metas = append(r.Metas, &Metadata{Key: strings.TrimSpace(metaTmp[0]), Value: strings.TrimSpace(metaTmp[1])})
		}
	case "sid":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no value for option sid")
		}
		sid, err := strconv.Atoi(nextItem.value)
		if err != nil {
			return fmt.Errorf("invalid sid %s", nextItem.value)
		}
		r.SID = sid
	case "rev":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return errors.New("no value for option rev")
		}
		rev, err := strconv.Atoi(nextItem.value)
		if err != nil {
			return fmt.Errorf("invalid rev %s", nextItem.value)
		}
		r.Revision = rev
	case "msg":
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValueString {
			return errors.New("no value for option msg")
		}
		r.Description = nextItem.value
	case "file_data":
		dataPosition = fileData
	case "pkt_data":
		dataPosition = pktData
	case "base64_data":
		dataPosition = base64Data
	case "content", "uricontent":
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
	case "http_cookie", "http_raw_cookie", "http_method", "http_header", "http_raw_header",
		"http_uri", "http_raw_uri", "http_user_agent", "http_stat_code", "http_stat_msg",
		"http_client_body", "http_server_body", "nocase":
		if len(r.Contents) == 0 {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		lastContent := r.Contents[len(r.Contents)-1]
		lastContent.Options = append(lastContent.Options, &ContentOption{Name: key.value})
	case "depth", "distance", "offset", "within":
		if len(r.Contents) == 0 {
			return fmt.Errorf("invalid content option %q with no content match", key.value)
		}
		nextItem := l.nextItem()
		if nextItem.typ != itemOptionValue {
			return fmt.Errorf("no value for content option %s", key.value)
		}
		v, err := strconv.Atoi(nextItem.value)
		if err != nil {
			return fmt.Errorf("invalid value %s for option %s", nextItem.value, key.value)
		}
		lastContent := r.Contents[len(r.Contents)-1]
		lastContent.Options = append(lastContent.Options, &ContentOption{Name: key.value, Value: v})
	case "fast_pattern":
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
	case "pcre":
		nextItem := l.nextItem()
		negate := false
		if nextItem.typ == itemNot {
			nextItem = l.nextItem()
			negate = true
		}
		if nextItem.typ == itemOptionValueString {
			p, err := parsePCRE(nextItem.value)
			if err != nil {
				return err
			}
			p.Negate = negate
			r.PCREs = append(r.PCREs, p)
		} else {
			return fmt.Errorf("invalid type %q for option content", nextItem.typ)
		}
	}
	return nil
}

// ParseRule parses an IDS rule and returns a struct describing the rule.
func ParseRule(rule string) (*Rule, error) {
	l, err := lex(rule)
	if err != nil {
		return nil, err
	}
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
