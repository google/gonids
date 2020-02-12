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
	// Contents are all the decoded content matches.
	Tags map[string]string
	// Statements is a slice of string. These items are similar to Tags, but have no value. (e.g. 'sameip;')
	Statements []string
	// TLSTags is a slice of TLS related matches.
	TLSTags []*TLSTag
	// StreamMatch holds stream_size parameters.
	StreamMatch *StreamCmp
	// Metas is a slice of Metadata.
	Metas Metadatas
	// Flowbits is a slice of Flowbit.
	Flowbits []*Flowbit
	// Xbits is a slice of Xbit
	Xbits []*Xbit
	// Flowints is a slice of Flowint
	Flowints []*Flowint
	// Matchers are internally used to ensure relative matches are printed correctly.
	// Make this private before checkin?
	Matchers []orderedMatcher
}

type orderedMatcher interface {
	String() string
}

// Metadata describes metadata tags in key-value struct.
type Metadata struct {
	Key   string
	Value string
}

// Flowbit describes a flowbit. A flowbit consists of an Action, and optional Value.
type Flowbit struct {
	Action string
	Value  string
}

// Flowint describes a flowint.
type Flowint struct {
	Name     string
	Modifier string
	Value    string
}

// Xbit describes an Xbit.
// TODO: Consider adding more structure to Track and Expire.
type Xbit struct {
	Action string
	Name   string
	Track  string
	// Expire should be an int, default 0 value makes stringer difficult because this is an
	// optional parameter. If we can confirm that this must be > 0 we can convert to int.
	Expire string
}

// Metadatas allows for a Stringer on []*Metadata
type Metadatas []*Metadata

// Network describes the IP addresses and port numbers used in a rule.
// TODO: Ensure all values either begin with $ (variable) or they are valid IPNet/int.
type Network struct {
	Nets  []string // Currently just []string because these can be variables $HOME_NET, not a valid IPNet.
	Ports []string // Currently just []string because these can be variables $HTTP_PORTS, not just ints.
}

// DataPos indicates the data position for content matches. These should be referenced for creation
// by using their Suricata keywords and the StickyBuffer() function.
type DataPos int

const (
	pktData DataPos = iota
	fileData
	base64Data
	//
	// Suricata 4.x Sticky Buffers
	//
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
	//
	// Suricata 5.0 Sticky Buffers
	//
	fileData5
	// HTTP Sticky Buffers
	httpAccept5
	httpAcceptEnc5
	httpAcceptLang5
	httpClientBody
	httpConnection5
	httpContentLen5
	httpContentType5
	httpCookie
	httpHeader
	httpHeaderNames5
	httpHeaderRaw
	httpHost
	httpHostRaw
	httpLocation
	httpMethod
	httpProtocol5
	httpReferer5
	httpRequestBody
	httpRequestLine5
	httpResponseBody
	httpResponseLine5
	httpServer
	httpServerBody
	httpStart5
	httpStatCode
	httpStatMsg
	httpURI
	httpURIRaw
	httpUserAgent
	// TLS Sticky Buffers
	tlsCertSubject5
	tlsCertIssuer5
	tlsCertSerial5
	tlsCertFingerprint5
	tlsSNI5
	// JA3 Sticky Buffers
	ja3Hash5
	ja3String5
	ja3sHash
	ja3sString
	// SSH Sticky Buffers
	sshProto5
	sshSoftware5
	// Kerberos Sticky Buffers - Unchanged from Suricata 4.x
	// DNS Sticky Buffers
	dnsQuery5
	// SMB - Documentation lacking. Unknown.
)

// Contains both Suricata 4.x and 5.0 buffers. Some day we'll deprecate the 4.x ones.
var stickyBuffers = map[DataPos]string{
	pktData:    "pkt_data",
	fileData:   "file_data",
	base64Data: "base64_data",
	// Suricata 4.X Sticky Buffers
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
	// Suricata 5.0 Sticky Buffers
	fileData5: "file.data",
	// HTTP Sticky Buffers
	httpAccept5:       "http.accept",
	httpAcceptEnc5:    "http.accept_enc",
	httpAcceptLang5:   "http.accept_lang",
	httpClientBody:    "http.client_body",
	httpConnection5:   "http.connection",
	httpContentLen5:   "http.content_len",
	httpContentType5:  "http.content_type",
	httpCookie:        "http.cookie",
	httpHeader:        "http.header",
	httpHeaderNames5:  "http.header_names",
	httpHeaderRaw:     "http.header.raw",
	httpHost:          "http.host",
	httpHostRaw:       "http.host.raw",
	httpLocation:      "http.location",
	httpMethod:        "http.method",
	httpProtocol5:     "http.protocol",
	httpReferer5:      "http.referer",
	httpRequestBody:   "http.request_body",
	httpRequestLine5:  "http.request_line",
	httpResponseBody:  "http.response_body",
	httpResponseLine5: "http.response_line",
	httpServer:        "http.server",
	httpServerBody:    "http.server_body",
	httpStart5:        "http.start",
	httpStatCode:      "http.stat_code",
	httpStatMsg:       "http.stat_msg",
	httpURI:           "http.uri",
	httpURIRaw:        "http.uri.raw",
	httpUserAgent:     "http.user_agent",
	// TLS Sticky Buffers
	tlsCertSubject5:     "tls.cert_subject",
	tlsCertIssuer5:      "tls.cert_issuer",
	tlsCertSerial5:      "tls.cert_serial",
	tlsCertFingerprint5: "tls.cert_fingerprint",
	tlsSNI5:             "tls.sni",
	// JA3 Sticky Buffers
	ja3Hash5:   "ja3.hash",
	ja3String5: "ja3.string",
	ja3sHash:   "ja3s.hash",
	ja3sString: "ja3s.string",
	// SSH Sticky Buffers
	sshProto5:    "ssh.proto",
	sshSoftware5: "ssh.software",
	// Kerberos Sticky Buffers - Unchanged from Suricata 4.x
	// DNS Sticky Buffers
	dnsQuery5: "dns.query",
	// SMB - Documentation lacking. Unknown.
}

func (d DataPos) String() string {
	return stickyBuffers[d]
}

// StickyBuffer returns the data position value for the string representation of a sticky buffer name (e.g. "file_data")
func StickyBuffer(s string) (DataPos, error) {
	for k, v := range stickyBuffers {
		if v == s {
			return k, nil
		}
	}
	return pktData, fmt.Errorf("%s is not a sticky buffer", s)
}

// isStickyBuffer returns true if the provided string is a known sticky buffer.
func isStickyBuffer(s string) bool {
	_, err := StickyBuffer(s)
	return err == nil
}

// Content describes a rule content. A content is composed of a pattern followed by options.
type Content struct {
	// DataPosition defaults to pkt_data state, can be modified to apply to file_data, base64_data locations.
	// This value will apply to all following contents, to reset to default you must reset DataPosition during processing.
	DataPosition DataPos
	// FastPattern settings for the content.
	FastPattern FastPattern
	// Pattern is the pattern match of a content (e.g. HTTP in content:"HTTP").
	Pattern []byte
	// Negate is true for negated content match.
	Negate bool
	// Options are the option associated to the content (e.g. http_header).
	Options []*ContentOption
}

// byteMatchType describes the kinds of byte matches and comparisons that are supported.
type byteMatchType int

const (
	bUnknown byteMatchType = iota
	bExtract
	bTest
	bJump
	isDataAt
	b64Decode
)

var byteMatchTypeVals = map[byteMatchType]string{
	bExtract:  "byte_extract",
	bJump:     "byte_jump",
	bTest:     "byte_test",
	isDataAt:  "isdataat",
	b64Decode: "base64_decode",
}

// allbyteMatchTypeNames returns a slice of valid byte_* keywords.
func allbyteMatchTypeNames() []string {
	b := make([]string, len(byteMatchTypeVals))
	var i int
	for _, n := range byteMatchTypeVals {
		b[i] = n
		i++
	}
	return b
}

// String returns the string representation of a byte_* keyword.
func (b byteMatchType) String() string {
	return byteMatchTypeVals[b]
}

// byteMatcher returns a byteMatchType iota for a provided String.
func byteMatcher(s string) (byteMatchType, error) {
	for k, v := range byteMatchTypeVals {
		if v == s {
			return k, nil
		}
	}
	return bUnknown, fmt.Errorf("%s is not a byteMatchType* keyword", s)
}

// lenMatcher returns an lenMatchType or an error for a given string.
func lenMatcher(s string) (lenMatchType, error) {
	for k, v := range lenMatchTypeVals {
		if v == s {
			return k, nil
		}
	}
	return lUnknown, fmt.Errorf("%s is not an lenMatch keyword", s)
}

// Returns the number of mandatory parameters for a byteMatchType keyword, -1 if unknown.
func (b byteMatchType) minLen() int {
	switch b {
	case bExtract:
		return 3
	case bJump:
		return 2
	case bTest:
		return 4
	case isDataAt:
		return 1
	case b64Decode:
		return 0
	}
	return -1
}

// ByteMatch describes a byte matching operation, similar to a Content.
type ByteMatch struct {
	// DataPosition defaults to pkt_data state, can be modified to apply to file_data, base64_data locations.
	// This value will apply to all following contents, to reset to default you must reset DataPosition during processing.
	DataPosition DataPos
	// Kind is a specific operation type we're taking.
	Kind byteMatchType
	// Negate indicates negation of a value, currently only used for isdataat.
	Negate bool
	// A variable name being extracted by byte_extract.
	Variable string
	// Number of bytes to operate on. "bytes to convert" in Snort Manual. This can be an int, or a var from byte_extract.
	NumBytes string
	// Operator for comparison in byte_test.
	Operator string
	// Value to compare against using byte_test.
	Value string
	// Offset within given buffer to operate on.
	Offset int
	// Other specifics required for jump/test here. This might make sense to pull out into a "ByteMatchOption" later.
	Options []string
}

// lenMatchType describes the type of length matches and comparisons that are supported.
type lenMatchType int

const (
	lUnknown lenMatchType = iota
	iType
	iCode
	iID
	iSeq
	uriLen
	dSize
	ipTTL
	ipID
	tcpSeq
	tcpACK
	bSize
)

// lenMatchTypeVals map len types to string representations.
var lenMatchTypeVals = map[lenMatchType]string{
	iType:  "itype",
	iCode:  "icode",
	iID:    "icmp_id",
	iSeq:   "icmp_seq",
	uriLen: "urilen",
	dSize:  "dsize",
	ipTTL:  "ttl",
	ipID:   "id",
	tcpSeq: "seq",
	tcpACK: "ack",
	bSize:  "bsize",
}

// allLenMatchTypeNames returns a slice of string containing all length match keywords.
func allLenMatchTypeNames() []string {
	i := make([]string, len(lenMatchTypeVals))
	var j int
	for _, n := range lenMatchTypeVals {
		i[j] = n
		j++
	}
	return i
}

// String returns the string keyword for an lenMatchType.
func (i lenMatchType) String() string {
	return lenMatchTypeVals[i]
}

// LenMatch holds the values to represent an Length Match.
type LenMatch struct {
	// DataPosition defaults to pkt_data state, can be modified to apply to file_data, base64_data locations.
	// This value will apply to all following contents, to reset to default you must reset DataPosition during processing.
	DataPosition DataPos
	Kind         lenMatchType
	Min          int
	Max          int
	Num          int
	Operator     string
	Options      []string
}

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

// TODO: Add support for tls_cert_nobefore, tls_cert_notafter, tls_cert_expired, tls_cert_valid.
// Valid keywords for extracting TLS matches. Does not include tls.store, or sticky buffers.
var tlsTags = []string{"ssl_version", "ssl_state", "tls.version", "tls.subject", "tls.issuerdn", "tls.fingerprint"}

// TLSTag describes a TLS specific match (non-sticky buffer based).
type TLSTag struct {
	// Is the match negated (!).
	Negate bool
	// Key holds the thing we're inspecting (tls.version, tls.fingerprint, etc.).
	Key string
	// TODO: Consider string -> []byte and handle hex input.
	// TODO: Consider supporting []struct if we can support things like: tls.version:!1.2,!1.3
	// Value holds the value for the match.
	Value string
}

// StreamCmp represents a stream comparison (stream_size:>20).
type StreamCmp struct {
	// Direction of traffic to inspect: server, client, both, either.
	Direction string
	// Operator is the comparison operator to apply >, <, !=, etc.
	Operator string
	// TODO: Can this number be a variable, if yes s/int/string.
	// Number is the size to compare against
	Number int
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
	for _, c := range r.Contents() {
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

// LenMatchers returns all *LenMatch for a rule.
func (r *Rule) LenMatchers() []*LenMatch {
	lms := make([]*LenMatch, 0, len(r.Matchers))
	for _, m := range r.Matchers {
		if lm, ok := m.(*LenMatch); ok {
			lms = append(lms, lm)
		}
	}
	return lms
}

// Contents returns all *Content for a rule.
func (r *Rule) Contents() []*Content {
	cs := make([]*Content, 0, len(r.Matchers))
	for _, m := range r.Matchers {
		if c, ok := m.(*Content); ok {
			cs = append(cs, c)
		}
	}
	return cs
}

// LastContent returns the last *Content from Matchers
func (r *Rule) LastContent() *Content {
	for i := range r.Matchers {
		if co, ok := r.Matchers[len(r.Matchers)-i-1].(*Content); ok {
			return co
		}
	}
	return nil
}

// ByteMatchers returns all *ByteMatch for a rule.
func (r *Rule) ByteMatchers() []*ByteMatch {
	bs := make([]*ByteMatch, 0, len(r.Matchers))
	for _, m := range r.Matchers {
		if b, ok := m.(*ByteMatch); ok {
			bs = append(bs, b)
		}
	}
	return bs
}

// PCREs returns all *PCRE for a rule.
func (r *Rule) PCREs() []*PCRE {
	var ps []*PCRE
	for _, m := range r.Matchers {
		if p, ok := m.(*PCRE); ok {
			ps = append(ps, p)
		}
	}
	return ps
}

func netString(netPart []string) string {
	var s strings.Builder
	if len(netPart) > 1 {
		s.WriteString("[")
	}
	for i, n := range netPart {
		s.WriteString(n)
		if i < len(netPart)-1 {
			s.WriteString(",")
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
	if f.Offset != 0 || f.Length != 0 {
		s.WriteString(fmt.Sprintf(":%d,%d", f.Offset, f.Length))
	}

	s.WriteString(";")
	return s.String()
}

// String returns a string for a ContentOption.
func (co ContentOption) String() string {
	if inSlice(co.Name, []string{"depth", "distance", "offset", "within"}) {
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

// base64DecodeString returns a string for a base64_decode ByteMatch.
func (b ByteMatch) base64DecodeString() string {
	var parts []string
	if b.NumBytes != "" {
		parts = append(parts, fmt.Sprintf("bytes %s", b.NumBytes))
	}
	if b.Offset > 0 {
		parts = append(parts, fmt.Sprintf("offset %d", b.Offset))
	}
	// This should only be "relative" but we'll support "anything"
	parts = append(parts, b.Options...)
	if len(parts) == 0 {
		return fmt.Sprintf("%s;", byteMatchTypeVals[b.Kind])
	}
	return fmt.Sprintf("%s:%s;", byteMatchTypeVals[b.Kind], strings.Join(parts, ","))
}

// String returns a string for a ByteMatch.
func (b ByteMatch) String() string {
	// TODO: Support dataPos?
	// TODO: Write tests.
	var s strings.Builder
	s.WriteString(fmt.Sprintf("%s:", byteMatchTypeVals[b.Kind]))

	switch b.Kind {
	case bExtract:
		s.WriteString(fmt.Sprintf("%s,%d,%s", b.NumBytes, b.Offset, b.Variable))
	case bJump:
		s.WriteString(fmt.Sprintf("%s,%d", b.NumBytes, b.Offset))
	case bTest:
		s.WriteString(fmt.Sprintf("%s,%s,%s,%d", b.NumBytes, b.Operator, b.Value, b.Offset))
	case isDataAt:
		if b.Negate {
			s.WriteString("!")
		}
		s.WriteString(b.NumBytes)
	// Logic for this case is a bit different so it's handled outside.
	case b64Decode:
		return b.base64DecodeString()
	}
	for _, o := range b.Options {
		s.WriteString(fmt.Sprintf(",%s", o))
	}
	s.WriteString(";")
	return s.String()
}

// String returns a string for an length match.
func (i LenMatch) String() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("%s:", i.Kind))
	switch {
	case i.Operator == "<>":
		s.WriteString(fmt.Sprintf("%d%s%d", i.Min, i.Operator, i.Max))
	case i.Operator != "":
		s.WriteString(fmt.Sprintf("%s%d", i.Operator, i.Num))
	default:
		s.WriteString(fmt.Sprintf("%d", i.Num))
	}
	for _, o := range i.Options {
		s.WriteString(fmt.Sprintf(",%s", o))
	}
	s.WriteString(";")
	return s.String()
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

func (t *TLSTag) String() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("%s:", t.Key))
	if t.Negate {
		s.WriteString("!")
	}
	// Values for these get wrapped in `"`.
	if inSlice(t.Key, []string{"tls.issuerdn", "tls.subject", "tls.fingerprint"}) {
		s.WriteString(fmt.Sprintf(`"%s";`, t.Value))
	} else {
		s.WriteString(fmt.Sprintf("%s;", t.Value))
	}
	return s.String()
}

func (s *StreamCmp) String() string {
	return fmt.Sprintf("stream_size:%s,%s,%d;", s.Direction, s.Operator, s.Number)
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

// String returns a string for a Flowbit.
func (fb Flowbit) String() string {
	if !inSlice(fb.Action, []string{"noalert", "isset", "isnotset", "set", "unset", "toggle"}) {
		return ""
	}
	var s strings.Builder
	s.WriteString(fmt.Sprintf("flowbits:%s", fb.Action))
	if fb.Value != "" {
		s.WriteString(fmt.Sprintf(",%s", fb.Value))
	}
	s.WriteString(";")
	return s.String()
}

// String returns a string for a Flowbit.
func (fi Flowint) String() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("flowint:%s", fi.Name))
	if inSlice(fi.Modifier, []string{"isset", "isnotset"}) {
		s.WriteString(fmt.Sprintf(",%s", fi.Modifier))
	}
	if inSlice(fi.Modifier, []string{"+", "-", "=", ">", "<", ">=", "<=", "==", "!="}) && fi.Value != "" {
		s.WriteString(fmt.Sprintf(",%s,%s", fi.Modifier, fi.Value))
	}
	s.WriteString(";")
	return s.String()
}

// String returns a string for a Flowbit.
func (xb Xbit) String() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("xbits:%s,%s,track %s", xb.Action, xb.Name, xb.Track))
	if xb.Expire != "" {
		s.WriteString(fmt.Sprintf(",expire %s", xb.Expire))
	}
	s.WriteString(";")
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

	// Pull flow out of tags if it exists, we like flow at the beginning of rules.
	if v, ok := r.Tags["flow"]; ok {
		s.WriteString(fmt.Sprintf("flow:%s; ", v))
	}

	// Write out matchers in order (because things can be relative.)
	if len(r.Matchers) > 0 {
		d := pktData
		for _, m := range r.Matchers {
			if c, ok := m.(*Content); ok {
				if d != c.DataPosition {
					d = c.DataPosition
					s.WriteString(fmt.Sprintf("%s; ", d))
				}
			}
			if c, ok := m.(*LenMatch); ok {
				if d != c.DataPosition {
					d = c.DataPosition
					s.WriteString(fmt.Sprintf("%s; ", d))
				}
			}
			s.WriteString(fmt.Sprintf("%s ", m))
		}
	}

	if r.StreamMatch != nil {
		s.WriteString(fmt.Sprintf("%s ", r.StreamMatch))
	}

	if len(r.TLSTags) > 0 {
		for _, t := range r.TLSTags {
			s.WriteString(fmt.Sprintf("%s ", t))
		}
	}

	if len(r.Metas) > 0 {
		s.WriteString(fmt.Sprintf("%s ", r.Metas))
	}

	for k, v := range r.Tags {
		if k == "flow" {
			continue
		}
		s.WriteString(fmt.Sprintf("%s:%s; ", k, v))
	}

	for _, v := range r.Statements {
		s.WriteString(fmt.Sprintf("%s; ", v))
	}

	for _, fb := range r.Flowbits {
		s.WriteString(fmt.Sprintf("%s ", fb))
	}

	for _, fi := range r.Flowints {
		s.WriteString(fmt.Sprintf("%s ", fi))
	}

	for _, xb := range r.Xbits {
		s.WriteString(fmt.Sprintf("%s ", xb))
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
		if b != ' ' && (b > 126 || b < 35 || b == ':' || b == ';' || b == '|') {
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

// InsertMatcher will insert an ordered matcher at a position specified.
func (r *Rule) InsertMatcher(m orderedMatcher, pos int) error {
	if pos < 0 {
		return fmt.Errorf("cannot insert matcher, position %d < 0", pos)
	}
	if pos > len(r.Matchers) {
		return fmt.Errorf("cannot insert matcher, position %d > %d", pos, len(r.Matchers))
	}

	r.Matchers = append(r.Matchers, &Content{})
	copy(r.Matchers[pos+1:], r.Matchers[pos:])
	r.Matchers[pos] = m
	return nil
}

// HasVar returns true if a variable with the provided name exists.
func (r *Rule) HasVar(s string) bool {
	for _, m := range r.Matchers {
		if b, ok := m.(*ByteMatch); ok {
			if b.Variable == s {
				return true
			}
		}
	}
	return false
}

// GetSidMsg returns a string representing a sidmsg.map entry.
func (r *Rule) GetSidMsg() string {
	var sidmsg strings.Builder
	sidmsg.WriteString(fmt.Sprintf("%s || %s", strconv.Itoa(r.SID), r.Description))
	for _, ref := range r.References {
		sidmsg.WriteString(fmt.Sprintf(" || %s,%s", ref.Type, ref.Value))
	}
	return sidmsg.String()
}
