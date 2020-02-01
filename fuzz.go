/* Copyright 2019 Google Inc.

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

// FuzzParseRule is used by OSS-Fuzz to fuzz the library.
func FuzzParseRule(data []byte) int {
	r, err := ParseRule(string(data))
	if err != nil {
		// Handle parse error
		return 0
	}
	r.OptimizeHTTP()
	_ = r.String()
	return 1
}
