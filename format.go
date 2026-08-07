/* Copyright 2026 Google Inc.

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
	"bufio"
	"io"
)

// Format reads an IDS rule file or stream from r and writes canonically formatted output to w.
// Non-rule lines (such as comments and blank lines) are preserved as-is.
// Active and disabled rules (including multi-line rules) are formatted using Rule.String().
func Format(r io.Reader, w io.Writer) error {
	scanner := NewRuleScanner(r)
	scanner.IncludeComments = true
	writer := bufio.NewWriter(w)

	for scanner.Scan() {
		if rule := scanner.Rule(); rule != nil {
			if _, err := writer.WriteString(rule.String() + "\n"); err != nil {
				return err
			}
		} else {
			if _, err := writer.WriteString(scanner.Raw() + "\n"); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return writer.Flush()
}
