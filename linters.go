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

// ShouldBeHTTP returns true if a rule looks like the protocol should be http, but is not.
func (r *Rule) ShouldBeHTTP() bool {
	var isHTTP bool
	// If the rule is already HTTP, then stop looking.
	if r.Protocol == "http" {
		return false
	}
	// If we look at http buffers or sticky buffers, we should use the HTTP protocol.
	for _, c := range r.Contents {
		if strings.HasPrefix(c.DataPosition.String(), "http_") {
			isHTTP = true
			break
		}
		for _, co := range c.Options {
			if strings.HasPrefix(co.Name, "http_") {
				isHTTP = true
				break
			}
		}
	}
	return isHTTP
}
