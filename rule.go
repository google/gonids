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
	Contents Contents
	// PCREs is a slice of PCRE structs that represent the regular expressions in a rule.
	PCREs []*PCRE
	// Tags is a map of tag names to tag values (e.g. classtype:trojan).
	Tags map[string]string
	// Vars is a map of variable names to variable values extracted via byte_extract.
	Vars map[string]*Var
	// Metas is a slice of Metadata.
	Metas Metadatas
}

// Var describes a variable extracted via byte_extract.
type Var struct {
	NumBytes int
	Offset   int
	Options  []string
}

// Metadata describes metadata tags in key-value struct.
type Metadata struct {
	Key   string
	Value string
}

// Metadatas allows for a Stringer on []*Metadata
type Metadatas []*Metadata

// TODO: Ensure all values either begin with $ (variable) or they are valid IPNet/int.
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
	// HTTP Sticky buffers
	httpAcceptEnc
	httpAccept
	httpAcceptLang
	httpConnection
	httpContentLen
	httpContentType
	httpHeaderNames
	httpProtocol
	httpReferer
	httpRequestLine
	httpResponseLine
	httpStart
	// TLS Sticky Buffers
	tlsCertSubject
	tlsCertIssuer
	tlsCertSerial
	tlsCertFingerprint
	tlsSNI
	// JA3 Sticky Buffers
	ja3Hash
	ja3String
	// SSH Sticky Buffers
	sshProto
	sshSoftware
	// Kerberos Sticky Buffers
	krb5Cname
	krb5Sname
	// DNS Sticky Buffers
	dnsQuery
	// SMB Sticky Buffers
	smbNamedPipe
	smbShare
)

var stickyBuffers = map[dataPos]string{
	pktData:    "pkt_data",
	fileData:   "file_data",
	base64Data: "base64_data",
	// HTTP Sticky Buffers
	httpAcceptEnc:    "http_accept_enc",
	httpAccept:       "http_accept",
	httpAcceptLang:   "http_accept_lang",
	httpConnection:   "http_connection",
	httpContentLen:   "http_content_len",
	httpContentType:  "http_content_type",
	httpHeaderNames:  "http_header_names",
	httpProtocol:     "http_protocol",
	httpReferer:      "http_referer",
	httpRequestLine:  "http_request_line",
	httpResponseLine: "http_response_line",
	httpStart:        "http_start",
	// TLS Sticky Buffers
	tlsCertSubject:     "tls_cert_subject",
	tlsCertIssuer:      "tls_cert_issuer",
	tlsCertSerial:      "tls_cert_serial",
	tlsCertFingerprint: "tls_cert_fingerprint",
	tlsSNI:             "tls_sni",
	// JA3 Sticky Buffers
	ja3Hash:   "ja3_hash",
	ja3String: "ja3_string",
	// SSH Sticky Buffers
	sshProto:    "ssh_proto",
	sshSoftware: "ssh_software",
	// Kerberos Sticky Buffers
	krb5Cname: "krb5_cname",
	krb5Sname: "krb5_sname",
	// DNS Sticky Buffers
	dnsQuery: "dns_query",
	// SMB Sticky Buffers
	smbNamedPipe: "smb_named_pipe",
	smbShare:     "smb_share",
}

func (d dataPos) String() string {
	return stickyBuffers[d]
}

// StickyBuffer returns the data position value for the string representation of a sticky buffer name (e.g. "file_data")
func StickyBuffer(s string) (dataPos, error) {
	for k, v := range stickyBuffers {
		if v == s {
			return k, nil
		}
	}
	return pktData, fmt.Errorf("not a sticky buffer")
}

func isStickyBuffer(s string) bool {
	_, err := StickyBuffer(s)
	return err == nil
}

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

// Contents is used so we can have a target type for a Stringer.
type Contents []*Content

// PCRE describes a PCRE item of a rule.
type PCRE struct {
	Pattern []byte
	Negate  bool
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
	// Value is the value associated to the option, default to "" for option without value.
	Value string
}

// Reference describes a gonids reference in a rule.
type Reference struct {
	// Type is the system name for the reference: (url, cve, md5, etc.)
	Type string
	// Value is the identifier in the system: (address, cvd-id, hash)
	Value string
}

// escape escapes special char used in regexp.
func escape(r string) string {
	return escapeRE.ReplaceAllString(r, `\$1`)
}

// within returns the within value for a specific content.
func within(options []*ContentOption) string {
	for _, o := range options {
		if o.Name == "within" {
			return o.Value
		}
	}
	return ""
}

// RE returns all content matches as a single and simple regexp.
func (r *Rule) RE() string {
	var re string
	for _, c := range r.Contents {
		// TODO: handle pcre, depth, offset, distance.
		if d, err := strconv.Atoi(within(c.Options)); err == nil && d > 0 {
			re += fmt.Sprintf(".{0,%d}", d)
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

func netString(netPart []string) string {
	var s strings.Builder
	if len(netPart) > 1 {
		s.WriteString("[")
	}
	for i, n := range netPart {
		s.WriteString(n)
		if i < len(netPart)-1 {
			s.WriteString(", ")
		}
	}
	if len(netPart) > 1 {
		s.WriteString("]")
	}
	return s.String()
}

// String retunrs a string for a Network.
func (n Network) String() string {
	return fmt.Sprintf("%s %s", netString(n.Nets), netString(n.Ports))
}

// String returns a string for a FastPattern.
func (f FastPattern) String() string {
	if !f.Enabled {
		return ""
	}
	// This is an invalid state.
	if f.Only && (f.Offset != 0 || f.Length != 0) {
		return ""
	}

	var s strings.Builder
	s.WriteString("fast_pattern")
	if f.Only {
		s.WriteString(":only;")
		return s.String()
	}

	// "only" and "chop" modes are mutually exclusive.
	if f.Offset != 0 && f.Length != 0 {
		s.WriteString(fmt.Sprintf(":%d,%d", f.Offset, f.Length))
	}

	s.WriteString(";")
	return s.String()
}

// String returns a string for a ContentOption.
func (co ContentOption) String() string {
	if inSlice(co.Name, []string{"byte_extract", "depth", "distance", "offset", "within"}) {
		return fmt.Sprintf("%s:%v;", co.Name, co.Value)
	}
	return fmt.Sprintf("%s;", co.Name)
}

// String returns a string for a Reference.
func (r Reference) String() string {
	return fmt.Sprintf("reference:%s,%s;", r.Type, r.Value)
}

// String returns a string for a Content (ignoring sticky buffers.)
func (c Content) String() string {
	var s strings.Builder
	s.WriteString("content:")
	if c.Negate {
		s.WriteString("!")
	}
	s.WriteString(fmt.Sprintf(`"%s";`, c.FormatPattern()))
	for _, o := range c.Options {
		s.WriteString(fmt.Sprintf(" %s", o))
	}
	if c.FastPattern.Enabled {
		s.WriteString(fmt.Sprintf(" %s", c.FastPattern))
	}

	return s.String()
}

// String returns a string for all of the contents.
func (cs Contents) String() string {
	var s strings.Builder
	d := pktData
	for _, c := range cs {
		if d != c.DataPosition {
			d = c.DataPosition
			s.WriteString(fmt.Sprintf(" %s;", d))
		}
		s.WriteString(fmt.Sprintf(" %s", c))
	}
	return strings.TrimSpace(s.String())
}

// String returns a string for all of the metadata values.
func (ms Metadatas) String() string {
	var s strings.Builder
	if len(ms) < 1 {
		return ""
	}
	s.WriteString("metadata:")
	for i, m := range ms {
		if i < len(ms)-1 {
			s.WriteString(fmt.Sprintf("%s %s, ", m.Key, m.Value))
			continue
		}
		s.WriteString(fmt.Sprintf("%s %s;", m.Key, m.Value))
	}
	return s.String()
}

// String returns a string for a PCRE.
func (p PCRE) String() string {
	pattern := p.Pattern
	if len(pattern) < 1 {
		return ""
	}

	// escape quote signs, if necessary
	if bytes.IndexByte(pattern, '"') > -1 {
		pattern = bytes.Replace(pattern, []byte(`"`), []byte(`\"`), -1)
	}

	var s strings.Builder
	s.WriteString("pcre:")
	if p.Negate {
		s.WriteString("!")
	}
	s.WriteString(fmt.Sprintf(`"/%s/%s";`, pattern, p.Options))
	return s.String()
}

// String returns a string for a rule.
func (r Rule) String() string {
	var s strings.Builder
	if r.Disabled {
		s.WriteString("#")
	}
	s.WriteString(fmt.Sprintf("%s %s %s ", r.Action, r.Protocol, r.Source))
	if !r.Bidirectional {
		s.WriteString("-> ")
	} else {
		s.WriteString("<> ")
	}

	s.WriteString(fmt.Sprintf(`%s (msg:"%s"; `, r.Destination, r.Description))

	if len(r.Contents) > 0 {
		s.WriteString(fmt.Sprintf("%s ", r.Contents))
	}

	for _, p := range r.PCREs {
		s.WriteString(fmt.Sprintf("%s ", p))
	}

	if len(r.Metas) > 0 {
		s.WriteString(fmt.Sprintf("%s ", r.Metas))
	}

	for k, v := range r.Tags {
		s.WriteString(fmt.Sprintf("%s:%s; ", k, v))
	}

	for _, ref := range r.References {
		s.WriteString(fmt.Sprintf("%s ", ref))
	}

	s.WriteString(fmt.Sprintf("sid:%d; rev:%d;)", r.SID, r.Revision))
	return s.String()

}

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
