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
	"bytes"
	"strings"
	"testing"
)

func TestFormat(t *testing.T) {
	input := `# Header comment
# $Id: rules.rules,v 1.1 2026/08/07 00:00:00 ids Exp $

alert tcp $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"multi-line rule"; \
    content:"evil"; \
    sid:1002; rev:2;)

# Section 2
alert ip any any -> any any (msg:"foo"; sid:1; rev:1;)

#alert tcp any any -> any any \
#    (msg:"disabled rule"; \
#    sid:1003; rev:1;)
`

	want := `# Header comment
# $Id: rules.rules,v 1.1 2026/08/07 00:00:00 ids Exp $

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"multi-line rule"; content:"evil"; sid:1002; rev:2;)

# Section 2
alert ip any any -> any any (msg:"foo"; sid:1; rev:1;)

#alert tcp any any -> any any (msg:"disabled rule"; sid:1003; rev:1;)
`

	var buf bytes.Buffer
	if err := Format(strings.NewReader(input), &buf); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	got := buf.String()
	if got != want {
		t.Fatalf("Format result mismatch:\n--- GOT ---\n%s\n--- WANT ---\n%s", got, want)
	}
}

func TestFormatError(t *testing.T) {
	input := `# Header
alert tcp any any -> any any (msg:"bad rule"; sid:invalid; rev:1;)
`
	var buf bytes.Buffer
	err := Format(strings.NewReader(input), &buf)
	if err == nil {
		t.Fatal("expected error from Format on invalid rule, got nil")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("expected error to mention line 2, got: %v", err)
	}
}
