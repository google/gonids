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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulefmtStdout(t *testing.T) {
	input := `alert tcp $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"test rule"; sid:1; rev:1;)
`
	var out bytes.Buffer
	if err := processFile("<standard input>", strings.NewReader(input), &out); err != nil {
		t.Fatalf("processFile failed: %v", err)
	}

	want := `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test rule"; sid:1; rev:1;)
`
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}

	var dashOut bytes.Buffer
	if err := processFile("-", strings.NewReader(input), &dashOut); err != nil {
		t.Fatalf("processFile with '-' failed: %v", err)
	}
	if dashOut.String() != want {
		t.Errorf("got %q, want %q", dashOut.String(), want)
	}
}

func TestRulefmtInPlace(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.rules")

	input := `# Header
alert tcp $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"multi-line test"; sid:100; rev:1;)
`
	if err := os.WriteFile(filePath, []byte(input), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	*write = true
	*list = false
	*doDiff = false
	*check = false
	exitCode = 0

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}

	var out bytes.Buffer
	if err := processFile(filePath, f, &out); err != nil {
		t.Fatalf("processFile failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close test file: %v", err)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	want := `# Header
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"multi-line test"; sid:100; rev:1;)
`
	if string(content) != want {
		t.Errorf("in-place file content:\ngot:  %q\nwant: %q", string(content), want)
	}
}

func TestRulefmtListAndDiff(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.rules")

	input := `alert tcp any any -> any any \
    (msg:"test"; sid:1; rev:1;)
`
	if err := os.WriteFile(filePath, []byte(input), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Test -l
	*write = false
	*list = true
	*doDiff = false
	*check = false
	exitCode = 0

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	var listOut bytes.Buffer
	if err := processFile(filePath, f, &listOut); err != nil {
		t.Fatalf("processFile failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close test file: %v", err)
	}

	if !strings.Contains(listOut.String(), filePath) {
		t.Errorf("-l output missing %s: got %q", filePath, listOut.String())
	}

	// Test -d
	*list = false
	*doDiff = true
	f2, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	var diffOut bytes.Buffer
	if err := processFile(filePath, f2, &diffOut); err != nil {
		t.Fatalf("processFile failed: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("failed to close test file: %v", err)
	}

	if !strings.Contains(diffOut.String(), "diff") {
		t.Errorf("-d output missing diff: got %q", diffOut.String())
	}
}

func TestRulefmtCheck(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.rules")

	input := `alert tcp any any -> any any \
    (msg:"unformatted"; sid:1; rev:1;)
`
	if err := os.WriteFile(filePath, []byte(input), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	*write = false
	*list = false
	*doDiff = false
	*check = true
	exitCode = 0

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	var out bytes.Buffer
	if err := processFile(filePath, f, &out); err != nil {
		t.Fatalf("processFile failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close test file: %v", err)
	}

	if exitCode != 1 {
		t.Errorf("expected exitCode 1 on unformatted file, got %d", exitCode)
	}
}

func TestRulefmtLint(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.rules")

	input := `alert tcp any any -> any any (msg:"missing sid"; rev:1;)
`
	if err := os.WriteFile(filePath, []byte(input), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	*lint = true
	*write = false
	*list = false
	*doDiff = false
	*check = false
	exitCode = 0

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}

	var out bytes.Buffer
	if err := processFile(filePath, f, &out); err != nil {
		t.Fatalf("processFile failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close test file: %v", err)
	}
}
