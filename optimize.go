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
func (r *Rule) SnortURILenFix() {
	// Update this once we parse urilen in a better structure.
	for tag, val := range r.Tags {
		if tag != "urilen" {
			continue
		}
		// Parse out int[operator]int
		// rex := regexp.MustCompile(val, "<>]+""), etc.
		// fmt.Println(rex.Split(foo, -1))
		// This omits the operator, so we need to do something about that too.

		// Then min -1, max +1 to make the equivalent value.
	}
}

// MetadataModifier returns a metadata that identifies a given modification.
func MetadataModifier(s string) *Metadata {
	return &Metadata{Key: "gonids", Value: s}
}
