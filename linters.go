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
	"strings"
)

// ShouldBeHTTP returns true if a rule looks like the protocol should be http, but is not.
func (r *Rule) ShouldBeHTTP() bool {
	// If the rule is already HTTP, then stop looking.
	if r.Protocol == "http" {
		return false
	}
	// If we look at http buffers or sticky buffers, we should use the HTTP protocol.
	for _, c := range r.Contents() {
		if strings.HasPrefix(c.DataPosition.String(), "http_") {
			return true
		}
		for _, co := range c.Options {
			if strings.HasPrefix(co.Name, "http_") {
				return true
			}
		}
	}
	return false
}

// TODO: See if ET folks have any data around this.
// Minimum length of a content to be considered safe for use with a PCRE.
const minPCREContentLen = 5

// Some of these may be caught by min length check, but including for completeness.
// All lower case for case insenstive checks.
// Many of this come from: https://github.com/EmergingThreats/IDSDeathBlossom/blob/master/config/fpblacklist.txt
var bannedContents = []string{"get",
	"post",
	"/",
	"user-agent",
	"user-agent: mozilla",
	"host",
	"index.php",
	"index.php?id=",
	"index.html",
	"content-length",
	".htm",
	".html",
	".php",
	".asp",
	".aspx",
	"content-disposition",
	"wp-content/plugins",
	"wp-content/themes",
	"activexobject",
	"default.asp",
	"default.aspx",
	"default.asp",
}

// ExpensivePCRE returns true if a rule appears to use a PCRE without
// conditions that make it expensive to compute.
func (r *Rule) ExpensivePCRE() bool {
	// No PCRE, not expensive.
	if len(r.PCREs()) < 1 {
		return false
	}

	// If we have PCRE, but no contents, this is probably expensive.
	cs := r.Contents()
	if len(cs) < 1 {
		return true
	}

	// Look for a content with sufficient length to make performance acceptable.
	short := true
	for _, c := range cs {
		// TODO: Identify a sane length.
		if len(c.Pattern) >= minPCREContentLen {
			short = false
		}
	}
	if short {
		return true
	}

	// If all content matches are common strings, also not good.
	common := true
	for _, c := range cs {
		if !inSlice(strings.ToLower(strings.Trim(string(c.Pattern), "\r\n :/?")), bannedContents) {
			return false
		}
	}
	if common {
		return true
	}

	// Don't flag a rule if we haven't defined a condition that's interesting.
	return false
}
