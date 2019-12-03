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

import (
	"testing"
)

func TestFuzz(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rule    string
	}{
		{
			name:    "fuzzer generated garbage",
			rule:    `alert tcp $EXTEVNAL_NET any <> $HOME_NET 0 e:misc-activity; sid:t 2010_09_#alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:"ET EXPLOIT xp_servicecontrol accecs"; flow:to_%erv23, upd)er,established; content:"x|00|p|00|_|00|s|00|e|00|r|00|v|00|i|00|c|00|e|00|c|00|o|00|n|00|t|00|r|00|o|00|l|00|"; nocase; reference:url,doc.emergi`,
		},
		{
			name:    "fuzzer goroutines sleep",
			rule:    `  ert htt $ET any -> Hnz (mjectatay; tls.fingerprint:"65`,
		},
	} {
		FuzzParseRule([]byte(tt.rule))
	}
}
