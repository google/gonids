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

import "strings"

// OptimizeHTTP tunes an old style rule to leverage port agnostic HTTP detection.
func (r *Rule) OptimizeHTTP() bool {
	var modify bool
	// Only attempt to modify rules that use HTTP buffers, but are not already HTTP.
	if r.Protocol == "http" {
		return false
	}
	for _, c := range r.Contents {
		if strings.HasPrefix(c.DataPosition.String(), "http_") {
			modify = true
			break
		}
		for _, co := range c.Options {
			if strings.HasPrefix(co.Name, "http_") {
				modify = true
				break
			}
		}
	}
	if !modify {
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

// MetadataModifier returns a metadata that identifies a given modification.
func MetadataModifier(s string) *Metadata {
	return &Metadata{Key: "gonids", Value: s}
}
