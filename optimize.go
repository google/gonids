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

// OptimizeHTTP tunes an old style rule to leverage port agnostic HTTP detection.
func (r *Rule) OptimizeHTTP() bool {
	if !r.ShouldBeHTTP() {
		return false
	}
	// Switch protocol to HTTP.
	r.Protocol = "http"

	// Make detection port agnostic.
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
	for i, m := range r.Matchers {
		// If this is a content, check it out.
		if c, ok := m.(*Content); ok {
			if c.SnortHTTPHeader() {
				modified = true
				c.Pattern = bytes.TrimSuffix(c.Pattern, []byte("\r\n"))
				if err := r.InsertMatcher(&ByteMatch{Kind: isDataAt, Negate: true, NumBytes: "1"}, i+1); err != nil {
					return false
				}
			}
		}
	}

	if modified {
		r.Metas = append(r.Metas, MetadataModifier("snort_http_header"))
	}
	return modified
}

// MetadataModifier returns a metadata that identifies a given modification.
func MetadataModifier(s string) *Metadata {
	return &Metadata{Key: "gonids", Value: s}
}
