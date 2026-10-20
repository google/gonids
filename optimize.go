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
)

// Suricata 4.x content options mapped to Suricata 5.0 sticky buffers.
var cOptToStickyBuffer = map[string]DataPos{
	// HTTP Content Modifiers
	"http_client_body":  httpClientBody,
	"http_cookie":       httpCookie,
	"http_header":       httpHeader,
	"http_host":         httpHost,
	"http_method":       httpMethod,
	"http_raw_header":   httpHeaderRaw,
	"http_raw_host":     httpHostRaw,
	"http_raw_uri":      httpURIRaw,
	"http_request_line": httpRequestLine5,
	"http_server_body":  httpServerBody,
	"http_stat_code":    httpStatCode,
	"http_stat_msg":     httpStatMsg,
	"http_uri":          httpURI,
	"http_user_agent":   httpUserAgent,
}

var suri4StickyTo5Sticky = map[DataPos]DataPos{
	fileData: fileData5,
	// HTTP
	httpAccept:       httpAccept5,
	httpAcceptEnc:    httpAcceptEnc5,
	httpAcceptLang:   httpAcceptLang5,
	httpConnection:   httpConnection5,
	httpContentLen:   httpContentLen5,
	httpContentType:  httpContentType5,
	httpHeaderNames:  httpHeaderNames5,
	httpProtocol:     httpProtocol5,
	httpReferer:      httpReferer5,
	httpRequestLine:  httpRequestLine5,
	httpResponseLine: httpResponseLine5,
	httpStart:        httpStart5,
	// TLS
	tlsCertSubject:     tlsCertSubject5,
	tlsCertIssuer:      tlsCertIssuer5,
	tlsCertSerial:      tlsCertSerial5,
	tlsCertFingerprint: tlsCertFingerprint5,
	tlsSNI:             tlsSNI5,
	// JA3
	ja3Hash:   ja3Hash5,
	ja3String: ja3String5,
	// SSH
	sshProto:    sshProto5,
	sshSoftware: sshSoftware5,
	// DNS
	dnsQuery: dnsQuery5,
}

// OptimizeHTTP tunes an old style rule to leverage port independent HTTP detection.
func (r *Rule) OptimizeHTTP() bool {
	if !r.ShouldBeHTTP() {
		return false
	}
	// Switch protocol to HTTP.
	r.Protocol = "http"

	// Make detection port independent.
	for i, p := range r.Source.Ports {
		if p == "$HTTP_PORTS" {
			r.Source.Ports[i] = "any"
		}
	}

	for i, p := range r.Destination.Ports {
		if p == "$HTTP_PORTS" {
			r.Destination.Ports[i] = "any"
		}
	}

	// Annotate rule to indicate modification
	r.Metas = append(r.Metas, MetadataModifier("http_optimize"))
	return true
}

// SnortURILenFix will optimize a urilen keyword from a Snort rule for Suricata.
func (r *Rule) SnortURILenFix() bool {
	var modified bool
	// Update this once we parse urilen in a better structure.
	for _, l := range r.LenMatchers() {
		if l.Kind == uriLen && l.Operator == "<>" {
			l.Min--
			l.Max++
			modified = true
		}
		setRaw := true
		for _, o := range l.Options {
			if o == "norm" || o == "raw" {
				// If Snort rule specified norm or raw, trust author.
				setRaw = false
				break
			}
		}
		// If author did not specify, set 'raw'.
		if setRaw {
			modified = true
			l.Options = append(l.Options, "raw")
		}
	}
	if modified {
		r.Metas = append(r.Metas, MetadataModifier("snort_urilen"))
	}
	return modified
}

// SnortHTTPHeaderFix will fix broken http_header matches.
func (r *Rule) SnortHTTPHeaderFix() bool {
	var modified bool
	if !r.SnortHTTPHeader() {
		return false
	}
	// Index r.Matchers directly: InsertMatcher grows the slice, so a range
	// over it would keep using stale indexes and a stale backing array.
	for i := 0; i < len(r.Matchers); i++ {
		// If this is a content, check it out.
		if c, ok := r.Matchers[i].(*Content); ok {
			if c.SnortHTTPHeader() {
				modified = true
				c.Pattern = bytes.TrimSuffix(c.Pattern, []byte("\r\n"))
				if err := r.InsertMatcher(&ByteMatch{Kind: isDataAt, Negate: true, NumBytes: "1"}, i+1); err != nil {
					return false
				}
				// Skip the isdataat we just inserted.
				i++
			}
		}
	}

	if modified {
		r.Metas = append(r.Metas, MetadataModifier("snort_http_header"))
	}
	return modified
}

// UpgradeToSuri5 optimizes a Suricata 4.x rule to Suricata 5.x features.
func (r *Rule) UpgradeToSuri5() bool {
	var modified bool
	for _, c := range r.Contents() {
		// Filter the old modifiers out in place. Removing them while ranging
		// over c.Options skips the following option and reads the nil'd tail.
		opts := c.Options[:0]
		for _, opt := range c.Options {
			if sticky, ok := cOptToStickyBuffer[opt.Name]; ok {
				c.DataPosition = sticky
				modified = true
				continue
			}
			opts = append(opts, opt)
		}
		for i := len(opts); i < len(c.Options); i++ {
			c.Options[i] = nil
		}
		c.Options = opts
		// old sticky buffer to new sticky buffer
		if sticky, ok := suri4StickyTo5Sticky[c.DataPosition]; ok {
			c.DataPosition = sticky
			modified = true
		}
	}

	if modified {
		r.Metas = append(r.Metas, MetadataModifier("upgrade_to_suri5"))
	}
	return modified
}

// MetadataModifier returns a metadata that identifies a given modification.
func MetadataModifier(s string) *Metadata {
	return &Metadata{Key: "gonids", Value: s}
}
