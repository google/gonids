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
	"strings"
	"testing"
)

func TestRuleScanner(t *testing.T) {
	input := `# Header comment
# $Id: rules.rules,v 1.1 2026/08/07 00:00:00 ids Exp $

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"single line rule"; sid:1001; rev:1;)

# Section comment
alert udp $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"multi-line rule with continuations"; \
    content:"evil"; \
    sid:1002; rev:2;)

#alert tcp any any -> any any \
#    (msg:"disabled multi-line rule"; \
#    content:"badness"; \
#    sid:1003; rev:3;)

# Trailing comments
`
	scanner := NewRuleScanner(strings.NewReader(input))

	// Rule 1
	if !scanner.Scan() {
		t.Fatalf("expected rule 1, got EOF/err: %v", scanner.Err())
	}
	r1 := scanner.Rule()
	if r1.SID != 1001 || r1.Description != "single line rule" || r1.Disabled {
		t.Errorf("rule 1 mismatch: %#v", r1)
	}
	if scanner.LineNumber() != 4 {
		t.Errorf("rule 1 LineNumber: got %d, expected 4", scanner.LineNumber())
	}
	wantRaw1 := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"single line rule"; sid:1001; rev:1;)`
	if scanner.Raw() != wantRaw1 {
		t.Errorf("rule 1 Raw:\ngot:  %q\nwant: %q", scanner.Raw(), wantRaw1)
	}

	// Rule 2
	if !scanner.Scan() {
		t.Fatalf("expected rule 2, got EOF/err: %v", scanner.Err())
	}
	r2 := scanner.Rule()
	if r2.SID != 1002 || r2.Description != "multi-line rule with continuations" || r2.Disabled {
		t.Errorf("rule 2 mismatch: %#v", r2)
	}
	if scanner.LineNumber() != 7 {
		t.Errorf("rule 2 LineNumber: got %d, expected 7", scanner.LineNumber())
	}
	wantRaw2 := `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"multi-line rule with continuations"; content:"evil"; sid:1002; rev:2;)`
	if scanner.Raw() != wantRaw2 {
		t.Errorf("rule 2 Raw:\ngot:  %q\nwant: %q", scanner.Raw(), wantRaw2)
	}

	// Rule 3 (Disabled)
	if !scanner.Scan() {
		t.Fatalf("expected rule 3, got EOF/err: %v", scanner.Err())
	}
	r3 := scanner.Rule()
	if r3.SID != 1003 || r3.Description != "disabled multi-line rule" || !r3.Disabled {
		t.Errorf("rule 3 mismatch: %#v", r3)
	}
	if scanner.LineNumber() != 12 {
		t.Errorf("rule 3 LineNumber: got %d, expected 12", scanner.LineNumber())
	}
	wantRaw3 := `#alert tcp any any -> any any (msg:"disabled multi-line rule"; content:"badness"; sid:1003; rev:3;)`
	if scanner.Raw() != wantRaw3 {
		t.Errorf("rule 3 Raw:\ngot:  %q\nwant: %q", scanner.Raw(), wantRaw3)
	}

	// EOF
	if scanner.Scan() {
		t.Fatalf("expected EOF, got extra rule: %#v", scanner.Rule())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("unexpected scanner error: %v", err)
	}
}

func TestRuleScannerError(t *testing.T) {
	input := `# Comment
alert tcp any any -> any any (msg:"broken rule"; sid:not_a_number; rev:1;)
`
	scanner := NewRuleScanner(strings.NewReader(input))
	if scanner.Scan() {
		t.Fatalf("expected scan to fail on broken rule, got rule: %#v", scanner.Rule())
	}
	if err := scanner.Err(); err == nil {
		t.Fatal("expected error for broken rule, got nil")
	} else if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("expected error message to mention line 2, got: %v", err)
	}
}
