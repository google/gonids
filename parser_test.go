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
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

func TestParseContent(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:  "simple content",
			input: "abcd",
			want:  []byte("abcd"),
		},
		{
			name:  "hex content",
			input: "A|42 43|D| 45|",
			want:  []byte("ABCDE"),
		},
		{
			name:  "contains hex pipe",
			input: "A|7C|B",
			want:  []byte("A|B"),
		},
		{
			name:  "escaped pipes around hex-looking content",
			input: `a\|41 41\|b`,
			want:  []byte(`a|41 41|b`),
		},
		{
			name:  "escaped pipes around valid hex",
			input: `\|dead\|`,
			want:  []byte(`|dead|`),
		},
		{
			name:  "hex block adjacent to escaped pipe",
			input: `\||41|`,
			want:  []byte("|A"),
		},
		{
			name:  "contains escaped backslash",
			input: `A\\B`,
			want:  []byte(`A\B`),
		},
		{
			name:  "contains multiple escaped characters",
			input: `A\\\;\"\\\:B`,
			want:  []byte(`A\;"\:B`),
		},
		{
			name:    "unescaped special characters",
			input:   `";`,
			wantErr: true,
		},
		{
			name:    "invalid escaping",
			input:   `\a\b\c`,
			wantErr: true,
		},
	} {
		got, err := parseContent(tt.input)
		if !reflect.DeepEqual(got, tt.want) || (err != nil) != tt.wantErr {
			t.Fatalf("%s: got %v,%v; expected %v,%v", tt.name, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestParseLenMatch(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		kind    lenMatchType
		want    *LenMatch
		wantErr bool
	}{
		{
			name:  "basic num",
			input: "6",
			kind:  uriLen,
			want: &LenMatch{
				Kind: uriLen,
				Num:  6,
			},
		},
		{
			name:  "less than",
			input: "<6",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Num:      6,
				Operator: "<",
			},
		},
		{
			name:  "greater than",
			input: ">6",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Num:      6,
				Operator: ">",
			},
		},
		{
			name:  "range",
			input: "4<>6",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Min:      4,
				Max:      6,
				Operator: "<>",
			},
		},
		{
			name:  "basic num, option",
			input: "6,raw",
			kind:  uriLen,
			want: &LenMatch{
				Kind:    uriLen,
				Num:     6,
				Options: []string{"raw"},
			},
		},
		{
			name:  "less than, option",
			input: "<6,raw",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Num:      6,
				Operator: "<",
				Options:  []string{"raw"},
			},
		},
		{
			name:  "greater than, option",
			input: ">6,raw",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Num:      6,
				Operator: ">",
				Options:  []string{"raw"},
			},
		},
		{
			name:  "range, option",
			input: "4<>6,raw",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Min:      4,
				Max:      6,
				Operator: "<>",
				Options:  []string{"raw"},
			},
		},
		{
			name:  "range, option with spaces",
			input: "4<>6,    raw",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Min:      4,
				Max:      6,
				Operator: "<>",
				Options:  []string{"raw"},
			},
		},
		{
			name:  "range, multi-option with spaces",
			input: "4<>6,    raw,  foo , bar",
			kind:  uriLen,
			want: &LenMatch{
				Kind:     uriLen,
				Min:      4,
				Max:      6,
				Operator: "<>",
				Options:  []string{"raw", "foo", "bar"},
			},
		},
		{
			name:  "simple bsize",
			input: "4",
			kind:  bSize,
			want: &LenMatch{
				Kind: bSize,
				Num:  4,
			},
		},
		{
			name:  "range bsize",
			input: "4<>6",
			kind:  bSize,
			want: &LenMatch{
				Kind:     bSize,
				Min:      4,
				Max:      6,
				Operator: "<>",
			},
		},
	} {
		got, err := parseLenMatch(tt.kind, tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

func TestParseByteMatch(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		kind    byteMatchType
		want    *ByteMatch
		wantErr bool
	}{
		{
			name:  "basic byte_extract",
			input: "3,0,Certs.len",
			kind:  bExtract,
			want: &ByteMatch{
				Kind:     bExtract,
				NumBytes: "3",
				Offset:   "0",
				Variable: "Certs.len",
			},
		},
		{
			name:  "byte_extract with options",
			input: "3,0,Certs.len, relative ,little",
			kind:  bExtract,
			want: &ByteMatch{
				Kind:     bExtract,
				NumBytes: "3",
				Offset:   "0",
				Variable: "Certs.len",
				Options:  []string{"relative", "little"},
			},
		},
		{
			name:  "byte_extract trims whitespace around variable name",
			input: "4, 0, Certs.len, relative",
			kind:  bExtract,
			want: &ByteMatch{
				Kind:     bExtract,
				NumBytes: "4",
				Offset:   "0",
				Variable: "Certs.len",
				Options:  []string{"relative"},
			},
		},
		{
			name:  "basic byte_jump",
			input: "3,0",
			kind:  bJump,
			want: &ByteMatch{
				Kind:     bJump,
				NumBytes: "3",
				Offset:   "0",
			},
		},
		{
			name:  "byte_jump with options",
			input: "3,0, relative, little",
			kind:  bJump,
			want: &ByteMatch{
				Kind:     bJump,
				NumBytes: "3",
				Offset:   "0",
				Options:  []string{"relative", "little"},
			},
		},
		{
			name:  "byte_jump with variable offset",
			input: "4, cn_len, relative",
			kind:  bJump,
			want: &ByteMatch{
				Kind:     bJump,
				NumBytes: "4",
				Offset:   "cn_len",
				Options:  []string{"relative"},
			},
		},

		{
			name:  "basic byte_test",
			input: "2,=,0x01,0",
			kind:  bTest,
			want: &ByteMatch{
				Kind:     bTest,
				NumBytes: "2",
				Operator: "=",
				Offset:   "0",
				Value:    "0x01",
			},
		},
		{
			name:  "byte_test with options",
			input: "4,=,1337,1,relative,string,dec",
			kind:  bTest,
			want: &ByteMatch{
				Kind:     bTest,
				NumBytes: "4",
				Operator: "=",
				Value:    "1337",
				Offset:   "1",
				Options:  []string{"relative", "string", "dec"},
			},
		},
		{
			name:  "isdataat",
			input: "4",
			kind:  isDataAt,
			want: &ByteMatch{
				Kind:     isDataAt,
				NumBytes: "4",
			},
		},
		{
			name:  "isdataat with options",
			input: "4,relative",
			kind:  isDataAt,
			want: &ByteMatch{
				Kind:     isDataAt,
				NumBytes: "4",
				Options:  []string{"relative"},
			},
		},
	} {
		got, err := parseByteMatch(tt.kind, tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

// TestByteExtractVariableWhitespace ensures a byte_extract variable defined with
// the common comma-space spacing still resolves when referenced by a later byte
// matcher. The variable name is stored trimmed, matching the trimmed references.
func TestByteExtractVariableWhitespace(t *testing.T) {
	for _, rule := range []string{
		`alert tcp any any -> any any (msg:"a"; byte_extract:4, 0, var1; byte_jump:var1, 0; sid:1; rev:1;)`,
		`alert tcp any any -> any any (msg:"b"; byte_extract:4, 0, var1; byte_test:var1, >, 5, 0; sid:2; rev:1;)`,
	} {
		r, err := ParseRule(rule)
		if err != nil {
			t.Fatalf("ParseRule(%q) returned error: %v", rule, err)
		}
		for _, b := range r.ByteMatchers() {
			if b.Kind == bExtract && b.Variable != "var1" {
				t.Fatalf("byte_extract variable = %q, want %q", b.Variable, "var1")
			}
		}
	}
}

func TestParseBase64Decode(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		kind    byteMatchType
		want    *ByteMatch
		wantErr bool
	}{
		{
			name:  "basic base64_decode",
			input: "",
			kind:  b64Decode,
			want: &ByteMatch{
				Kind: b64Decode,
			},
		},
		{
			name:  "bytes",
			input: "bytes  5  ",
			kind:  b64Decode,
			want: &ByteMatch{
				Kind:     b64Decode,
				NumBytes: "5",
			},
		},
		{
			name:  "offset",
			input: "offset  4",
			kind:  b64Decode,
			want: &ByteMatch{
				Kind:   b64Decode,
				Offset: "4",
			},
		},
		{
			name:  "random",
			input: "  relative,  offset  4, bytes     5",
			kind:  b64Decode,
			want: &ByteMatch{
				Kind:     b64Decode,
				NumBytes: "5",
				Offset:   "4",
				Options:  []string{"relative"},
			},
		},
		{
			name:  "offset 0",
			input: "offset 0",
			kind:  b64Decode,
			want: &ByteMatch{
				Kind:   b64Decode,
				Offset: "0",
			},
		},
		{
			name:  "offset 0 with bytes and relative",
			input: "bytes 100, offset 0, relative",
			kind:  b64Decode,
			want: &ByteMatch{
				Kind:     b64Decode,
				NumBytes: "100",
				Offset:   "0",
				Options:  []string{"relative"},
			},
		},
	} {
		got, err := parseBase64Decode(tt.kind, tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

func TestBase64DecodeBytesValidation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rule    string
		wantErr bool
	}{
		{
			name:    "bytes references byte_extract variable",
			rule:    `alert tcp any any -> any any (msg:"a"; byte_extract:4,0,mybytes; base64_decode:bytes mybytes; base64_data; content:"x"; sid:1; rev:1;)`,
			wantErr: false,
		},
		{
			name:    "bytes literal positive one",
			rule:    `alert tcp any any -> any any (msg:"e"; base64_decode:bytes 1; sid:5; rev:1;)`,
			wantErr: false,
		},
		{
			name:    "bytes literal positive integer",
			rule:    `alert tcp any any -> any any (msg:"f"; base64_decode:bytes 8; sid:6; rev:1;)`,
			wantErr: false,
		},
		{
			name:    "bytes literal zero",
			rule:    `alert tcp any any -> any any (msg:"b"; base64_decode:bytes 0; sid:2; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "bytes literal negative",
			rule:    `alert tcp any any -> any any (msg:"c"; base64_decode:bytes -5; sid:3; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "bytes unknown variable",
			rule:    `alert tcp any any -> any any (msg:"d"; base64_decode:bytes nope; sid:4; rev:1;)`,
			wantErr: true,
		},
	} {
		_, err := ParseRule(tt.rule)
		if (err != nil) != tt.wantErr {
			t.Fatalf("%s: ParseRule(%q) err = %v, wantErr = %v", tt.name, tt.rule, err, tt.wantErr)
		}
	}
}

func TestParseThreshold(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    *Threshold
		wantErr bool
	}{
		{
			name:  "standard limit by_src",
			input: "type limit, track by_src, count 1, seconds 60",
			want: &Threshold{
				Type:    "limit",
				Track:   "by_src",
				Count:   1,
				Seconds: 60,
			},
		},
		{
			name:  "standard both by_dst",
			input: "type both, track by_dst, count 50, seconds 300",
			want: &Threshold{
				Type:    "both",
				Track:   "by_dst",
				Count:   50,
				Seconds: 300,
			},
		},
		{
			name:  "backoff with multiplier",
			input: "type backoff, track by_flow, count 1, multiplier 10",
			want: &Threshold{
				Type:       "backoff",
				Track:      "by_flow",
				Count:      1,
				Multiplier: 10,
			},
		},
		{
			name:  "case-insensitive limit by_src",
			input: "TYPE LIMIT, TRACK BY_SRC, COUNT 5, SECONDS 120",
			want: &Threshold{
				Type:    "limit",
				Track:   "by_src",
				Count:   5,
				Seconds: 120,
			},
		},
		{
			name:    "invalid key-value",
			input:   "type",
			wantErr: true,
		},
		{
			name:    "invalid type",
			input:   "type unknown, track by_src, count 1, seconds 60",
			wantErr: true,
		},
		{
			name:    "invalid track",
			input:   "type limit, track unknown, count 1, seconds 60",
			wantErr: true,
		},
		{
			name:    "invalid count not an int",
			input:   "type limit, track by_src, count abc, seconds 60",
			wantErr: true,
		},
		{
			name:    "count zero",
			input:   "type limit, track by_src, count 0, seconds 60",
			wantErr: true,
		},
		{
			name:    "count negative",
			input:   "type limit, track by_src, count -1, seconds 60",
			wantErr: true,
		},
		{
			name:    "seconds zero",
			input:   "type limit, track by_src, count 1, seconds 0",
			wantErr: true,
		},
		{
			name:    "seconds negative",
			input:   "type limit, track by_src, count 1, seconds -60",
			wantErr: true,
		},
		{
			name:    "multiplier zero",
			input:   "type backoff, track by_flow, count 1, multiplier 0",
			wantErr: true,
		},
		{
			name:    "multiplier negative",
			input:   "type backoff, track by_flow, count 1, multiplier -10",
			wantErr: true,
		},
		{
			name:    "missing type",
			input:   "track by_src, count 1, seconds 60",
			wantErr: true,
		},
		{
			name:    "missing track",
			input:   "type limit, count 1, seconds 60",
			wantErr: true,
		},
		{
			name:    "missing count",
			input:   "type limit, track by_src, seconds 60",
			wantErr: true,
		},
		{
			name:    "backoff invalid track",
			input:   "type backoff, track by_src, count 1, multiplier 10",
			wantErr: true,
		},
		{
			name:    "backoff missing multiplier",
			input:   "type backoff, track by_flow, count 1",
			wantErr: true,
		},
		{
			name:    "backoff with seconds",
			input:   "type backoff, track by_flow, count 1, multiplier 10, seconds 60",
			wantErr: true,
		},
		{
			name:    "limit with multiplier",
			input:   "type limit, track by_src, count 1, seconds 60, multiplier 10",
			wantErr: true,
		},
	} {
		got, err := parseThreshold(tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

func TestParseDetectionFilter(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    *DetectionFilter
		wantErr bool
	}{
		{
			name:  "standard detection_filter",
			input: "track by_src, count 10, seconds 60",
			want: &DetectionFilter{
				Track:   "by_src",
				Count:   10,
				Seconds: 60,
			},
		},
		{
			name:  "with unique_on src_port",
			input: "track by_dst, count 5, seconds 30, unique_on src_port",
			want: &DetectionFilter{
				Track:    "by_dst",
				Count:    5,
				Seconds:  30,
				UniqueOn: "src_port",
			},
		},
		{
			name:  "case-insensitive with unique_on dst_port",
			input: "TRACK BY_SRC, COUNT 20, SECONDS 120, UNIQUE_ON DST_PORT",
			want: &DetectionFilter{
				Track:    "by_src",
				Count:    20,
				Seconds:  120,
				UniqueOn: "dst_port",
			},
		},
		{
			name:    "invalid key-value",
			input:   "track",
			wantErr: true,
		},
		{
			name:    "invalid track",
			input:   "track unknown, count 10, seconds 60",
			wantErr: true,
		},
		{
			name:    "invalid count not an int",
			input:   "track by_src, count abc, seconds 60",
			wantErr: true,
		},
		{
			name:    "count zero",
			input:   "track by_src, count 0, seconds 60",
			wantErr: true,
		},
		{
			name:    "count negative",
			input:   "track by_src, count -1, seconds 60",
			wantErr: true,
		},
		{
			name:    "seconds zero",
			input:   "track by_src, count 10, seconds 0",
			wantErr: true,
		},
		{
			name:    "seconds negative",
			input:   "track by_src, count 10, seconds -60",
			wantErr: true,
		},
		{
			name:    "missing track",
			input:   "count 10, seconds 60",
			wantErr: true,
		},
		{
			name:    "missing count",
			input:   "track by_src, seconds 60",
			wantErr: true,
		},
		{
			name:    "missing seconds",
			input:   "track by_src, count 10",
			wantErr: true,
		},
		{
			name:    "invalid unique_on",
			input:   "track by_src, count 10, seconds 60, unique_on invalid_port",
			wantErr: true,
		},
		{
			name:    "unknown parameter",
			input:   "track by_src, count 10, seconds 60, foo bar",
			wantErr: true,
		},
	} {
		got, err := parseDetectionFilter(tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

func TestParseFlowbit(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    *Flowbit
		wantErr bool
	}{
		{
			name:  "basic flowbit",
			input: "set,foo",
			want: &Flowbit{
				Action: "set",
				Value:  "foo",
			},
		},
		{
			name:  "reset action",
			input: "reset",
			want: &Flowbit{
				Action: "reset",
			},
		},
		{
			name:  "case-insensitive SET",
			input: "SET,FOO",
			want: &Flowbit{
				Action: "set",
				Value:  "FOO",
			},
		},
		{
			name:  "case-insensitive NOALERT",
			input: "NOALERT",
			want: &Flowbit{
				Action: "noalert",
			},
		},
		{
			name:  "case-insensitive RESET",
			input: "RESET",
			want: &Flowbit{
				Action: "reset",
			},
		},
		// Errors
		{
			name:    "not valid action",
			input:   "zoom,foo",
			wantErr: true,
		},
		{
			name:    "noalert with value",
			input:   "noalert,foo",
			wantErr: true,
		},
		{
			name:    "reset with value",
			input:   "reset,foo",
			wantErr: true,
		},
		{
			name:    "set missing value",
			input:   "set",
			wantErr: true,
		},
		{
			name:    "unset missing value",
			input:   "unset",
			wantErr: true,
		},
		{
			name:    "isset missing value",
			input:   "isset",
			wantErr: true,
		},
		{
			name:    "isnotset missing value",
			input:   "isnotset",
			wantErr: true,
		},
		{
			name:    "toggle missing value",
			input:   "toggle",
			wantErr: true,
		},
		{
			name:    "extra parts",
			input:   "set,foo,bar",
			wantErr: true,
		},
	} {
		got, err := parseFlowbit(tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

func TestParseXbit(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    *Xbit
		wantErr bool
	}{
		{
			name:  "basic xbit",
			input: "set,foo,track ip_src",
			want: &Xbit{
				Action: "set",
				Name:   "foo",
				Track:  "ip_src",
			},
		},
		{
			name:  "basic xbit expire",
			input: "set,foo,track ip_src,expire 60",
			want: &Xbit{
				Action: "set",
				Name:   "foo",
				Track:  "ip_src",
				Expire: "60",
			},
		},
		{
			name:  "funky spacing",
			input: "  set  ,   foo,   track   ip_src  , expire  60    ",
			want: &Xbit{
				Action: "set",
				Name:   "foo",
				Track:  "ip_src",
				Expire: "60",
			},
		},
		// Errors
		{
			name:    "not valid action",
			input:   "zoom,foo,track ip_src,expire 60",
			wantErr: true,
		},
		{
			name:    "invalid len",
			input:   "set,foo",
			wantErr: true,
		},
		{
			name:    "not track",
			input:   "set,foo,nottrack ip_src,",
			wantErr: true,
		},
		{
			name:    "not expire",
			input:   "set,foo,track ip_src,notexpire 60",
			wantErr: true,
		},
	} {
		got, err := parseXbit(tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

func TestParseFlowint(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    *Flowint
		wantErr bool
	}{
		{
			name:  "basic flowint",
			input: "foo,>,1",
			want: &Flowint{
				Name:     "foo",
				Modifier: ">",
				Value:    "1",
			},
		},
		{
			name:  "basic status",
			input: "foo,isnotset",
			want: &Flowint{
				Name:     "foo",
				Modifier: "isnotset",
			},
		},
		// Errors
		{
			name:    "too short",
			input:   "foo",
			wantErr: true,
		},
		{
			name:    "invalid modifier",
			input:   "foo,baz,bar",
			wantErr: true,
		},
	} {
		got, err := parseFlowint(tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
	}
}

func TestParseRule(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rule    string
		want    *Rule
		wantErr bool
		optErr  *UnsupportedOptionError
	}{
		{
			name: "test http1",
			rule: `alert http1 $HOME_NET any -> $EXTERNAL_NET any (msg:"test http1"; http.uri; content:"/index.html"; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http1",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Revision:    1,
				Description: "test http1",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("/index.html"),
					},
				},
			},
		},
		{
			name: "test ike",
			rule: `alert ike $HOME_NET any -> $EXTERNAL_NET any (msg:"test ike"; sid:2; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "ike",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         2,
				Revision:    1,
				Description: "test ike",
			},
		},
		{
			name: "test telnet",
			rule: `alert telnet $HOME_NET any -> $EXTERNAL_NET any (msg:"test telnet"; sid:3; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "telnet",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         3,
				Revision:    1,
				Description: "test telnet",
			},
		},
		{
			name: "test bittorrent-dht",
			rule: `alert bittorrent-dht $HOME_NET any -> $EXTERNAL_NET any (msg:"test bittorrent-dht"; sid:4; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "bittorrent-dht",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         4,
				Revision:    1,
				Description: "test bittorrent-dht",
			},
		},
		{
			name: "test quic",
			rule: `alert quic $HOME_NET any -> $EXTERNAL_NET any (msg:"test quic"; sid:5; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "quic",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         5,
				Revision:    1,
				Description: "test quic",
			},
		},
		{
			name: "test pgsql",
			rule: `alert pgsql $HOME_NET any -> $EXTERNAL_NET any (msg:"test pgsql"; sid:6; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "pgsql",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         6,
				Revision:    1,
				Description: "test pgsql",
			},
		},
		{
			name: "test tcp.hdr",
			rule: `alert tcp any any -> any any (msg:"test tcp.hdr"; tcp.hdr; content:"|00 00|"; sid:7; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         7,
				Revision:    1,
				Description: "test tcp.hdr",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: tcpHdr,
						Pattern:      []byte{0, 0},
					},
				},
			},
		},
		{
			name: "test tcp.flags",
			rule: `alert tcp any any -> any any (msg:"test tcp.flags"; tcp.flags; content:"|02|"; sid:8; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         8,
				Revision:    1,
				Description: "test tcp.flags",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: tcpFlags,
						Pattern:      []byte{2},
					},
				},
			},
		},
		{
			name: "test udp.hdr",
			rule: `alert udp any any -> any any (msg:"test udp.hdr"; udp.hdr; content:"|00 00|"; sid:9; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         9,
				Revision:    1,
				Description: "test udp.hdr",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: udpHdr,
						Pattern:      []byte{0, 0},
					},
				},
			},
		},
		{
			name: "test icmpv4.hdr",
			rule: `alert icmpv4 any any -> any any (msg:"test icmpv4.hdr"; icmpv4.hdr; content:"|08 00|"; sid:10; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "icmpv4",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         10,
				Revision:    1,
				Description: "test icmpv4.hdr",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: icmpv4Hdr,
						Pattern:      []byte{8, 0},
					},
				},
			},
		},
		{
			name: "test icmpv6.hdr",
			rule: `alert icmpv6 any any -> any any (msg:"test icmpv6.hdr"; icmpv6.hdr; content:"|80 00|"; sid:11; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "icmpv6",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         11,
				Revision:    1,
				Description: "test icmpv6.hdr",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: icmpv6Hdr,
						Pattern:      []byte{0x80, 0},
					},
				},
			},
		},
		{
			name: "test ipv6.hdr",
			rule: `alert ipv6 any any -> any any (msg:"test ipv6.hdr"; ipv6.hdr; content:"|60 00|"; sid:12; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "ipv6",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         12,
				Revision:    1,
				Description: "test ipv6.hdr",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: ipv6Hdr,
						Pattern:      []byte{0x60, 0},
					},
				},
			},
		},
		{
			name: "tls.certs sticky buffer",
			rule: `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"test tls.certs"; tls.certs; content:"Let's Encrypt"; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tls",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Revision:    1,
				Description: "test tls.certs",
				Matchers: []orderedMatcher{
					&Content{
						Pattern:      []byte("Let's Encrypt"),
						DataPosition: tlsCerts,
					},
				},
			},
		},
		{
			name: "tls.random sticky buffer",
			rule: `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"test tls.random"; tls.random; content:"|00 00 00 00|"; sid:2; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tls",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         2,
				Revision:    1,
				Description: "test tls.random",
				Matchers: []orderedMatcher{
					&Content{
						Pattern:      []byte{0, 0, 0, 0},
						DataPosition: tlsRandom,
					},
				},
			},
		},
		{
			name: "http.request_header sticky buffer",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"test http.request_header"; http.request_header; content:"User-Agent: evil"; sid:3; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         3,
				Revision:    1,
				Description: "test http.request_header",
				Matchers: []orderedMatcher{
					&Content{
						Pattern:      []byte("User-Agent: evil"),
						DataPosition: httpRequestHeader,
					},
				},
			},
		},
		{
			name: "http.response_header sticky buffer",
			rule: `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"test http.response_header"; http.response_header; content:"Server: Apache"; sid:4; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         4,
				Revision:    1,
				Description: "test http.response_header",
				Matchers: []orderedMatcher{
					&Content{
						Pattern:      []byte("Server: Apache"),
						DataPosition: httpResponseHeader,
					},
				},
			},
		},
		{
			name: "file.magic sticky buffer",
			rule: `alert http any any -> any any (msg:"test file.magic"; file.magic; content:"PE32 executable"; sid:5; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         5,
				Revision:    1,
				Description: "test file.magic",
				Matchers: []orderedMatcher{
					&Content{
						Pattern:      []byte("PE32 executable"),
						DataPosition: fileMagic,
					},
				},
			},
		},

		{
			name: "uppercase options",
			rule: `alert http any any -> any any (Msg:"test uppercase keywords"; Content:"Software.txt"; Content:"UserInformation.txt"; Sid:2044432; Rev:1; Classtype:trojan-activity; Flow:established,to_server;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         2044432,
				Revision:    1,
				Description: "test uppercase keywords",
				Tags: map[string]string{
					"classtype": "trojan-activity",
					"flow":      "established,to_server",
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("Software.txt"),
					},
					&Content{
						Pattern: []byte("UserInformation.txt"),
					},
				},
			},
		},
		{
			name: "chained transforms on content",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"test chained"; http.uri; to_lowercase; url_decode; content:"/test"; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Revision:    1,
				Description: "test chained",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("/test"),
						Transforms: []*Transform{
							{Name: "to_lowercase"},
							{Name: "url_decode"},
						},
					},
				},
				Metas:      Metadatas{},
				Tags:       map[string]string{},
				References: []*Reference{},
				Flowbits:   []*Flowbit{},
			},
		},
		{
			name: "chained transforms on content (dotprefix)",
			rule: `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"test dotprefix"; tls.sni; dotprefix; content:".google.com"; endswith; sid:2; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tls",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         2,
				Revision:    1,
				Description: "test dotprefix",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: tlsSNI5,
						Pattern:      []byte(".google.com"),
						Options: []*ContentOption{
							{Name: "endswith"},
						},
						Transforms: []*Transform{
							{Name: "dotprefix"},
						},
					},
				},
				Metas:      Metadatas{},
				Tags:       map[string]string{},
				References: []*Reference{},
				Flowbits:   []*Flowbit{},
			},
		},
		{
			name: "chained transforms on content (http2)",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"test http2"; http.header_names; strip_pseudo_headers; header_lowercase; content:"user-agent:"; sid:3; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         3,
				Revision:    1,
				Description: "test http2",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpHeaderNames5,
						Pattern:      []byte("user-agent:"),
						Transforms: []*Transform{
							{Name: "strip_pseudo_headers"},
							{Name: "header_lowercase"},
						},
					},
				},
				Metas:      Metadatas{},
				Tags:       map[string]string{},
				References: []*Reference{},
				Flowbits:   []*Flowbit{},
			},
		},
		{
			name: "chained transforms on content (pcrexform)",
			rule: `alert http any any -> any any (msg:"test pcrexform"; http.request_line; pcrexform:"[a-zA-Z]+\s+(.*)\s+HTTP"; content:"/dropper.php"; sid:4; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         4,
				Revision:    1,
				Description: "test pcrexform",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpRequestLine5,
						Pattern:      []byte("/dropper.php"),
						Transforms: []*Transform{
							{Name: "pcrexform", Value: `"[a-zA-Z]+\s+(.*)\s+HTTP"`},
						},
					},
				},
				Metas:      Metadatas{},
				Tags:       map[string]string{},
				References: []*Reference{},
				Flowbits:   []*Flowbit{},
			},
		},
		{
			name:    "non-rule comment",
			rule:    `# Foo header, this describes a file.`,
			wantErr: true,
		},
		{
			name: "comment end-rule",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; content:"bar"; sid:123; rev:1;) # foo comment.`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         123,
				Revision:    1,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("bar"),
					},
				},
			},
		},
		{
			name: "spaces in network object",
			rule: `alert tcp any any -> [1.1.1.1, 1.1.1.2] any (msg:"test"; content:"123"; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"1.1.1.1,1.1.1.2"},
					Ports: []string{"any"},
				},
				SID:         1,
				Revision:    1,
				Description: "test",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("123"),
					},
				},
			},
		},
		{
			name: "test byte_jump var",
			rule: `alert tcp any any -> any any (msg:"test byte_jump var"; byte_extract:2,0,cn_len; byte_jump:4,cn_len,relative; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Description: "test byte_jump var",
				Matchers: []orderedMatcher{
					&ByteMatch{
						Kind:     bExtract,
						NumBytes: "2",
						Offset:   "0",
						Variable: "cn_len",
					},
					&ByteMatch{
						Kind:     bJump,
						NumBytes: "4",
						Offset:   "cn_len",
						Options:  []string{"relative"},
					},
				},
				SID:      1,
				Revision: 1,
			},
		},
		{
			name: "simple content",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Revision:    2,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
		},
		{
			name: "negated tags",
			rule: `alert tcp any any -> any any (msg:"test"; fragbits:!M; flags:!F; tos:!0; ipopts:!rr; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         1,
				Revision:    1,
				Description: "test",
				Tags: map[string]string{
					"fragbits": "!M",
					"flags":    "!F",
					"tos":      "!0",
					"ipopts":   "!rr",
				},
			},
		},
		{
			name: "commented rule content",
			rule: `#alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2;)`,
			want: &Rule{
				Disabled: true,
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Revision:    2,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
		},
		{
			name: "bidirectional",
			rule: `alert udp $HOME_NET any <> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				Bidirectional: true,
				SID:           1337,
				Revision:      2,
				Description:   "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
		},
		{
			name: "not content",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:!"AA";)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"), Negate: true},
				},
			},
		},
		{
			name: "multiple contents",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; content:"BB";)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
					&Content{
						Pattern: []byte("BB"),
					},
				},
			},
		},
		{
			name: "hex content",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"A|42 43|D|45|";)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte{'A', 0x42, 0x43, 'D', 0x45},
					},
				},
			},
		},
		{
			name: "tags",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:!"AA"; classtype:foo;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Tags:        map[string]string{"classtype": "foo"},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"), Negate: true},
				},
			},
		},
		{
			name: "target tag",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:!"AA"; target:src_ip;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Target:      "src_ip",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"), Negate: true},
				},
			},
		},
		{
			name: "tls tag",
			rule: `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"tls_subject"; content:!"AA"; tls.subject:!"CN=*.googleusercontent.com"; classtype:foo; sid:1337; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tls",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Revision:    1,
				Description: "tls_subject",
				TLSTags: []*TLSTag{
					{
						Negate: true,
						Key:    "tls.subject",
						Value:  "CN=*.googleusercontent.com",
					},
				},
				Tags: map[string]string{"classtype": "foo"},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"), Negate: true},
				},
			},
		},
		{
			name: "dsize",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; dsize:>19;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     dSize,
						Operator: ">",
						Num:      19,
					},
				},
			},
		},
		{
			name: "urilen options",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; urilen:2<>7,raw;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     uriLen,
						Operator: "<>",
						Min:      2,
						Max:      7,
						Options:  []string{"raw"},
					},
				},
			},
		},
		{
			name: "stream_size",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; stream_size:both,>,19; sid:1337; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Revision:    1,
				Description: "foo",
				StreamMatch: &StreamCmp{
					Direction: "both",
					Operator:  ">",
					Number:    19,
				},
			},
		},
		{
			name: "icmp match",
			rule: `alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; itype:>10; sid:1337; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "icmp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Revision:    1,
				Description: "foo",
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     iType,
						Operator: ">",
						Num:      10,
					},
				},
			},
		},
		{
			name: "references",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"A"; reference:cve,2014; reference:url,www.suricata-ids.org;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				References: []*Reference{
					{Type: "cve", Value: "2014"},
					{Type: "url", Value: "www.suricata-ids.org"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("A"),
					},
				},
			},
		},
		{
			name: "content options",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:!"AA"; http_header; offset:3;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1337,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
						Negate:  true,
						Options: []*ContentOption{
							{"http_header", ""},
							{"offset", "3"},
						},
					},
				},
			},
		},
		{
			name: "multiple contents and options",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; content:"A"; http_header; fast_pattern; content:"B"; http_uri;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Description: "a",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("A"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
						FastPattern: FastPattern{Enabled: true},
					},
					&Content{
						Pattern: []byte("B"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
		},
		{
			name: "multiple contents and multiple options",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; content:"A"; http_header; fast_pattern:0,42; nocase; content:"B"; http_uri;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Description: "a",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("A"),
						Options: []*ContentOption{
							{"http_header", ""},
							{"nocase", ""},
						},
						FastPattern: FastPattern{Enabled: true, Offset: 0, Length: 42},
					},
					&Content{
						Pattern: []byte("B"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
		},
		{
			name: "multiple contents with file_data",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; file_data; content:"A"; http_header; nocase; content:"B"; http_uri;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Description: "a",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("A"),
						Options: []*ContentOption{
							{"http_header", ""},
							{"nocase", ""},
						},
					},
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("B"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
		},
		{
			name: "broken rule",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"broken rule"; content:"A"; content:"B"; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         12345,
				Revision:    1,
				Description: "broken rule",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("A"),
					},
					&Content{
						Pattern: []byte("B"),
					},
				},
			},
		},
		{
			name: "multiple contents with file_data and pkt_data",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; file_data; content:"A"; http_header; nocase; content:"B"; http_uri; pkt_data; content:"C"; http_uri;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Description: "a",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("A"),
						Options: []*ContentOption{
							{"http_header", ""},
							{"nocase", ""},
						},
					},
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("B"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
					&Content{
						DataPosition: pktData,
						Pattern:      []byte("C"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
		},
		{
			name: "http sticky buffer",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; http_request_line; content:"A"; content:"B"; pkt_data; content:"C"; http_uri;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Description: "a",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpRequestLine,
						Pattern:      []byte("A"),
					},
					&Content{
						DataPosition: httpRequestLine,
						Pattern:      []byte("B"),
					},
					&Content{
						DataPosition: pktData,
						Pattern:      []byte("C"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
		},
		{
			name: "DNS sticky buffer",
			rule: `alert dns any any -> any any (msg:"DNS Query for google.com"; dns_query; content:"google.com"; nocase; sid:1234; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "dns",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    1,
				Description: "DNS Query for google.com",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: dnsQuery,
						Pattern:      []byte("google.com"),
						Options: []*ContentOption{
							{"nocase", ""},
						},
					},
				},
			},
		},
		{
			name: "Complex VRT rule",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"VRT BLOCKLIST URI request for known malicious URI - /tongji.js"; flow:to_server,established; content:"/tongji.js"; fast_pattern:only; http_uri; content:"Host|3A| "; http_header; pcre:"/Host\x3a[^\r\n]*?\.tongji/Hi"; metadata:impact_flag red, policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,labs.snort.org/docs/17904.html; classtype:trojan-activity; sid:17904; rev:6;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets: []string{"$EXTERNAL_NET"}, Ports: []string{"$HTTP_PORTS"},
				},
				SID:         17904,
				Revision:    6,
				Description: "VRT BLOCKLIST URI request for known malicious URI - /tongji.js",
				References:  []*Reference{{Type: "url", Value: "labs.snort.org/docs/17904.html"}},
				Tags: map[string]string{
					"flow":      "to_server,established",
					"classtype": "trojan-activity",
				},
				Metas: Metadatas{
					&Metadata{Key: "impact_flag", Value: "red"},
					&Metadata{Key: "policy", Value: "balanced-ips drop"},
					&Metadata{Key: "policy", Value: "security-ips drop"},
					&Metadata{Key: "ruleset", Value: "community"},
					&Metadata{Key: "service", Value: "http"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("/tongji.js"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
						FastPattern: FastPattern{Enabled: true, Only: true},
					},
					&Content{
						Pattern: append([]byte("Host"), 0x3a, 0x20),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&PCRE{
						Pattern: []byte(`Host\x3a[^\r\n]*?\.tongji`),
						Options: []byte("Hi"),
					},
				},
			},
		},
		{
			name: "content and PCRE",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Foo msg"; flow:to_server,established; content:"blah"; http_uri; pcre:"/foo.*bar/Ui"; reference:url,www.google.com; classtype:trojan-activity; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets: []string{"$EXTERNAL_NET"}, Ports: []string{"$HTTP_PORTS"},
				},
				SID:         12345,
				Revision:    1,
				Description: "Foo msg",
				References: []*Reference{
					{
						Type:  "url",
						Value: "www.google.com"},
				},
				Tags: map[string]string{
					"flow":      "to_server,established",
					"classtype": "trojan-activity",
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("blah"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
					&PCRE{
						Pattern: []byte("foo.*bar"),
						Options: []byte("Ui"),
					},
				},
			},
		},
		{
			name: "Metadata",
			rule: `alert tcp any any -> any any (msg:"ET SHELLCODE Berlin Shellcode"; flow:established; content:"|31 c9 b1 fc 80 73 0c|"; content:"|43 e2 8b 9f|"; distance:0; reference:url,doc.emergingthreats.net/2009256; classtype:shellcode-detect; sid:2009256; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets: []string{"any"}, Ports: []string{"any"},
				},
				Destination: Network{
					Nets: []string{"any"}, Ports: []string{"any"},
				},
				SID:         2009256,
				Revision:    3,
				Description: "ET SHELLCODE Berlin Shellcode",
				References: []*Reference{
					{
						Type:  "url",
						Value: "doc.emergingthreats.net/2009256"},
				},
				Tags: map[string]string{"flow": "established", "classtype": "shellcode-detect"},
				Metas: Metadatas{
					&Metadata{Key: "created_at", Value: "2010_07_30"},
					&Metadata{Key: "updated_at", Value: "2010_07_30"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte{0x31, 0xc9, 0xb1, 0xfc, 0x80, 0x73, 0x0c},
					},
					&Content{
						Pattern: []byte{0x43, 0xe2, 0x8b, 0x9f},
						Options: []*ContentOption{
							{"distance", "0"},
						},
					},
				},
			},
		},
		{
			name: "Multi Metadata",
			rule: `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS Chase Account Phish Landing Oct 22"; flow:established,from_server; file_data; content:"<title>Sign in</title>"; content:"name=chalbhai"; fast_pattern; nocase; distance:0; content:"required title=|22|Please Enter Right Value|22|"; nocase; distance:0; content:"required title=|22|Please Enter Right Value|22|"; nocase; distance:0; metadata: former_category CURRENT_EVENTS; classtype:trojan-activity; sid:2025692; rev:2; metadata:created_at 2015_10_22, updated_at 2018_07_12;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         2025692,
				Revision:    2,
				Description: "ET CURRENT_EVENTS Chase Account Phish Landing Oct 22",
				Tags:        map[string]string{"flow": "established,from_server", "classtype": "trojan-activity"},
				Metas: Metadatas{
					&Metadata{Key: "former_category", Value: "CURRENT_EVENTS"},
					&Metadata{Key: "created_at", Value: "2015_10_22"},
					&Metadata{Key: "updated_at", Value: "2018_07_12"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern:      []byte("<title>Sign in</title>"),
						DataPosition: fileData,
					},
					&Content{
						Pattern:      []byte("name=chalbhai"),
						DataPosition: fileData,
						Options: []*ContentOption{
							{"nocase", ""},
							{"distance", "0"},
						},
						FastPattern: FastPattern{Enabled: true},
					},
					&Content{
						Pattern:      []byte{0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3d, 0x22, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22},
						DataPosition: fileData,
						Options: []*ContentOption{
							{"nocase", ""},
							{"distance", "0"},
						},
					},
					&Content{
						Pattern:      []byte{0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3d, 0x22, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22},
						DataPosition: fileData,
						Options: []*ContentOption{
							{"nocase", ""},
							{"distance", "0"},
						},
					},
				},
			},
		},
		{
			name: "Negated PCRE",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Negated PCRE"; pcre:!"/foo.*bar/Ui"; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				SID:         12345,
				Revision:    1,
				Description: "Negated PCRE",
				Matchers: []orderedMatcher{
					&PCRE{
						Pattern: []byte("foo.*bar"),
						Negate:  true,
						Options: []byte("Ui"),
					},
				},
			},
		},
		{
			name: "PCRE with quote",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"PCRE with quote"; pcre:"/=[.\"]\w{8}\.jar/Hi"; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				SID:         12345,
				Revision:    1,
				Description: "PCRE with quote",
				Matchers: []orderedMatcher{
					&PCRE{
						Pattern: []byte(`=[."]\w{8}\.jar`),
						Options: []byte("Hi"),
					},
				},
			},
		},
		{
			name: "byte_extract",
			rule: `alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"byte_extract"; content:"|ff fe|"; byte_extract:3,0,Certs.len, relative ,little ; content:"|55 04 0a 0c 0C|"; distance:3; within:Certs.len; sid:42; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"443"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         42,
				Revision:    1,
				Description: "byte_extract",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte{0xff, 0xfe},
					},
					&ByteMatch{
						Kind:     bExtract,
						NumBytes: "3",
						Offset:   "0",
						Variable: "Certs.len",
						Options:  []string{"relative", "little"},
					},
					&Content{
						Pattern: []byte{0x55, 0x04, 0x0A, 0x0C, 0x0C},
						Options: []*ContentOption{
							{"distance", "3"},
							{"within", "Certs.len"},
						},
					},
				},
			},
		},
		{
			name: "byte_test",
			rule: `alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"byte_test"; content:"|ff fe|"; byte_test:5,<,65537,0,relative,string; sid:42; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"443"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         42,
				Revision:    1,
				Description: "byte_test",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte{0xff, 0xfe},
					},
					&ByteMatch{
						Kind:     bTest,
						NumBytes: "5",
						Operator: "<",
						Value:    "65537",
						Offset:   "0",
						Options:  []string{"relative", "string"},
					},
				},
			},
		},
		{
			name: "byte_jump",
			rule: `alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"byte_jump"; content:"|ff fe|"; byte_jump:4,0,relative,little,post_offset -1; sid:42; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"443"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         42,
				Revision:    1,
				Description: "byte_jump",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte{0xff, 0xfe},
					},
					&ByteMatch{
						Kind:     bJump,
						NumBytes: "4",
						Offset:   "0",
						Options:  []string{"relative", "little", "post_offset -1"},
					},
				},
			},
		},
		{
			name: "negate isdataat",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"isdataat"; content:"aabb"; depth:4; byte_jump:2,3,post_offset -1; isdataat:!2,relative; sid:42; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         42,
				Revision:    1,
				Description: "isdataat",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("aabb"),
						Options: []*ContentOption{
							{"depth", "4"},
						},
					},
					&ByteMatch{
						Kind:     bJump,
						NumBytes: "2",
						Offset:   "3",
						Options:  []string{"post_offset -1"},
					},
					&ByteMatch{
						Kind:     isDataAt,
						Negate:   true,
						NumBytes: "2",
						Options:  []string{"relative"},
					},
				},
			},
		},
		{
			name: "base64 keywords offset 0",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test base64 keywords offset 0"; base64_decode:bytes 100, offset 0, relative; base64_data; content:"thing I see"; sid:123; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         123,
				Revision:    1,
				Description: "test base64 keywords offset 0",
				Matchers: []orderedMatcher{
					&ByteMatch{
						Kind:     b64Decode,
						NumBytes: "100",
						Offset:   "0",
						Options:  []string{"relative"},
					},
					&Content{
						DataPosition: base64Data,
						Pattern:      []byte("thing I see"),
					},
				},
			},
		},
		{
			name: "base64 keywords",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"test base64 keywords"; base64_decode:bytes 150,offset 17,relative; base64_data; content:"thing I see"; sid:123; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         123,
				Revision:    1,
				Description: "test base64 keywords",
				Matchers: []orderedMatcher{
					&ByteMatch{
						Kind:     b64Decode,
						NumBytes: "150",
						Offset:   "17",
						Options:  []string{"relative"},
					},
					&Content{
						DataPosition: base64Data,
						Pattern:      []byte("thing I see"),
					},
				},
			},
		},
		{
			name: "content with escaped characters",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"escaped characters"; content:"A\\B\;C\"\:"; sid:7; rev:1;)`, want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         7,
				Revision:    1,
				Description: "escaped characters",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte{0x41, 0x5c, 0x42, 0x3b, 0x43, 0x22, 0x3a},
					},
				},
			},
		},
		{
			name: "content and pcre order matters",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"check order"; content:"1"; pcre:"/this.*/R"; content:"2"; sid:1; rev:1;)`, want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1,
				Revision:    1,
				Description: "check order",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("1"),
					},
					&PCRE{
						Pattern: []byte(`this.*`),
						Options: []byte("R"),
					},
					&Content{
						Pattern: []byte("2"),
					},
				},
			},
		},
		{
			name: "flowbits",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Flowbits test"; flow:to_server,established; content:"testflowbits"; http_uri; flowbits:set,testbits; flowbits:noalert; classtype:test_page; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "Flowbits test",
				Tags: map[string]string{
					"flow":      "to_server,established",
					"classtype": "test_page",
				},
				Flowbits: []*Flowbit{
					{
						Action: "set",
						Value:  "testbits",
					},
					{
						Action: "noalert",
						Value:  "",
					},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("testflowbits"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
		},
		{
			name: "flowints",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Flowints test"; flowint:foo,+,1; flowint:bar,isset; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "Flowints test",
				Flowints: []*Flowint{
					{
						Name:     "foo",
						Modifier: "+",
						Value:    "1",
					},
					{
						Name:     "bar",
						Modifier: "isset",
					},
				},
			},
		},
		{
			name: "xbits",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Xbits test"; xbits:set,foo,track ip_src; xbits:set,bar,track ip_src,expire 60; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "Xbits test",
				Xbits: []*Xbit{
					{
						Action: "set",
						Name:   "foo",
						Track:  "ip_src",
					},
					{
						Action: "set",
						Name:   "bar",
						Track:  "ip_src",
						Expire: "60",
					},
				},
			},
		},
		// Begin Suricata 5.0 features.
		{
			name: "startswith",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"startswith test"; content:"foo"; startswith; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "startswith test",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
						Options: []*ContentOption{
							{"startswith", ""},
						},
					},
				},
			},
		},
		{
			name: "startswith and endswith",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"start and end test"; content:"foo"; startswith; endswith; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "start and end test",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
						Options: []*ContentOption{
							{"startswith", ""},
							{"endswith", ""},
						},
					},
				},
			},
		},
		{
			name: "new sticky buffers",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"new sticky buffers"; http.uri; content:"/foo"; content:"bar"; distance:0; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "new sticky buffers",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("/foo"),
					},
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("bar"),
						Options:      []*ContentOption{{"distance", "0"}},
					},
				},
			},
		},
		{
			name: "bsize simple",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"new sticky buffers"; http.uri; bsize:10; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "new sticky buffers",
				Matchers: []orderedMatcher{
					&LenMatch{
						DataPosition: httpURI,
						Kind:         bSize,
						Num:          10,
					},
				},
			},
		},
		{
			name: "bsize with contents and toggle",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"new sticky buffers"; http.method; content:"POST"; bsize:10; http.uri; content:"foo"; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "new sticky buffers",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpMethod,
						Pattern:      []byte("POST"),
					},
					&LenMatch{
						DataPosition: httpMethod,
						Kind:         bSize,
						Num:          10,
					},
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("foo"),
					},
				},
			},
		},
		{
			name: "grouped port test",
			rule: `alert http $HOME_NET [1:80,![2,4],[6,7,8]] -> $EXTERNAL_NET any (msg:"wat"; http.method; content:"POST"; http.uri; content:"foo"; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"1:80", "![2,4]", "[6,7,8]"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "wat",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpMethod,
						Pattern:      []byte("POST"),
					},
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("foo"),
					},
				},
			},
		},
		{
			name: "grouped network test",
			rule: `alert http [192.168.0.0/16,![192.168.86.0/24,192.168.87.0/24]] any -> $EXTERNAL_NET any (msg:"wat"; http.method; content:"POST"; http.uri; content:"foo"; sid:1234; rev:2;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"192.168.0.0/16", "![192.168.86.0/24,192.168.87.0/24]"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         1234,
				Revision:    2,
				Description: "wat",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpMethod,
						Pattern:      []byte("POST"),
					},
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("foo"),
					},
				},
			},
		},
		{
			name: "raw port list",
			rule: `alert tcp $EXTERNAL_NET [443,465,993,995,25] -> $HOME_NET any (msg:"raw port list"; content:"hi"; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"443,465,993,995,25"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         12345,
				Revision:    1,
				Description: "raw port list",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("hi"),
					},
				},
			},
		},
		{
			name: "raw port list with negations",
			rule: `alert tcp $EXTERNAL_NET [!21,!22,!23,!2100,!3535] -> $HOME_NET any (msg:"raw port list with negations"; content:"hi"; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"!21,!22,!23,!2100,!3535"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         12345,
				Revision:    1,
				Description: "raw port list with negations",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("hi"),
					},
				},
			},
		},
		{
			name: "negated port list",
			rule: `alert tcp any any -> any ![80,443,9000] (msg:"negated port list"; content:"123"; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:        []string{"any"},
					NegatePorts: true,
					Ports:       []string{"80,443,9000"},
				},
				Description: "negated port list",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("123"),
					},
				},
				SID:      1,
				Revision: 1,
			},
		},
		{
			name: "negated network list",
			rule: `alert tcp ![$HOME_NET,192.168.1.1] any -> any $HTTP_PORTS (msg:"negated port list"; content:"123"; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					NegateNets: true,
					Nets:       []string{"$HOME_NET,192.168.1.1"},
					Ports:      []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Description: "negated port list",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("123"),
					},
				},
				SID:      1,
				Revision: 1,
			},
		},
		{
			name: "raw network list",
			rule: `alert tcp [174.129.0.0/16,67.202.0.0/18] any -> $HOME_NET any (msg:"raw network list"; content:"hi"; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"174.129.0.0/16,67.202.0.0/18"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         12345,
				Revision:    1,
				Description: "raw network list",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("hi"),
					},
				},
			},
		},
		{
			name: "raw network list with negations",
			rule: `alert tcp [174.129.0.0/16,!67.202.0.0/18] any -> $HOME_NET any (msg:"raw network list"; content:"hi"; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"174.129.0.0/16,!67.202.0.0/18"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				SID:         12345,
				Revision:    1,
				Description: "raw network list",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("hi"),
					},
				},
			},
		},
		{
			name: "sticky buffer before content and PCRE",
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Foo msg"; flow:to_server,established; http.uri; content:"blah"; pkt_data; pcre:"/foo.*bar/i"; reference:url,www.google.com; classtype:trojan-activity; sid:12345; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets: []string{"$EXTERNAL_NET"}, Ports: []string{"$HTTP_PORTS"},
				},
				SID:         12345,
				Revision:    1,
				Description: "Foo msg",
				References: []*Reference{
					{
						Type:  "url",
						Value: "www.google.com"},
				},
				Tags: map[string]string{
					"flow":      "to_server,established",
					"classtype": "trojan-activity",
				},
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("blah"),
					},
					&PCRE{
						DataPosition: pktData,
						Pattern:      []byte("foo.*bar"),
						Options:      []byte("i"),
					},
				},
			},
		},
		{
			name: "content match with escaped pipe and characters",
			rule: `alert tcp any any -> any any (msg:"test"; content:"\|test\| \[abc\] \+ \. \ "; sid:1; rev:1;)`,
			want: &Rule{
				Action:      "alert",
				Protocol:    "tcp",
				Source:      Network{Nets: []string{"any"}, Ports: []string{"any"}},
				Destination: Network{Nets: []string{"any"}, Ports: []string{"any"}},
				SID:         1,
				Revision:    1,
				Description: "test",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: pktData,
						Pattern:      []byte("|test| [abc] + .  "),
					},
				},
			},
		},
		{
			name: "escaped pipe wrapping hex-looking content stays literal",
			rule: `alert tcp any any -> any any (msg:"test"; content:"a\|41 41\|b"; sid:1; rev:1;)`,
			want: &Rule{
				Action:      "alert",
				Protocol:    "tcp",
				Source:      Network{Nets: []string{"any"}, Ports: []string{"any"}},
				Destination: Network{Nets: []string{"any"}, Ports: []string{"any"}},
				SID:         1,
				Revision:    1,
				Description: "test",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: pktData,
						Pattern:      []byte("a|41 41|b"),
					},
				},
			},
		},
		// Errors
		{
			name:    "invalid action",
			rule:    `alertt udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2;)`,
			wantErr: true,
		},
		{
			name:    "invalid ip",
			rule:    `alert udp $HOME_NET any -> 0.0.0 any (sid:1337; msg:"foo"; dsize:>19;)`,
			wantErr: true,
		},
		{
			name:    "invalid protocol",
			rule:    `alertt udpp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2;)`,
			wantErr: true,
		},
		{
			name:    "invalid port",
			rule:    `alert tcp $HOME_NET any -> $EXTERNAL_NET 888888 (msg:"GONIDS TEST hello world"; flow:established,to_server; content:"hello world"; classtype:trojan-activity; sid:1; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "invalid direction",
			rule:    `alert udp $HOME_NET any *# $EXTERNAL_NET any (sid:2; msg:"foo"; content:"A";)`,
			wantErr: true,
		},
		{
			name:    "invalid sid",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:"a");`,
			wantErr: true,
		},
		{
			name:    "invalid content option",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; content:"foo"; offset:"a";)`,
			wantErr: true,
		},
		{
			name:    "invalid content value",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; content:!; offset:"a";)`,
			wantErr: true,
		},
		{
			name:    "invalid msg",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:2; msg; content:"A";)`,
			wantErr: true,
		},
		{
			name:    "invalid flowbits action",
			rule:    `alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"flowbits"; flowbits:TEST; sid:4321;)`,
			wantErr: true,
		},
		{
			name: "network with space",
			rule: `alert tcp $EXTERNAL_NET 443 -> $HOME_NET [123, 234] (msg:"bad network definition"; sid:4321;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"443"},
				},
				Destination: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"123,234"},
				},
				SID:         4321,
				Description: "bad network definition",
			},
		},
		{
			name:    "content with backslash at end",
			rule:    `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ending backslash rule"; content:"foo\"; sid:12345; rev:2;)`,
			wantErr: true,
		},
		{
			name:    "unbalanced network brackets",
			rule:    `alert http [10.0.0.0/24,![10.0.0.10,10.0.0.11] any -> $EXTERNAL_NET any (msg:"unbalanced"; content:"foo"; sid:12345; rev:2;)`,
			wantErr: true,
		},
		{
			name:    "unbalanced port brackets",
			rule:    `alert http $HOME_NET [1:80,![22,21] any -> $EXTERNAL_NET any (msg:"unbalanced"; content:"foo"; sid:12345; rev:2;)`,
			wantErr: true,
		},
		{
			name:    "unsupported option key",
			rule:    `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"unsupported option key"; content:"foo"; zibzab:1; foobar:"wat"; content:"baz"; sid:4321; rev:1;)`,
			wantErr: true,
			optErr: &UnsupportedOptionError{
				Rule: &Rule{
					Action:   "alert",
					Protocol: "http",
					Source: Network{
						Nets:  []string{"$HOME_NET"},
						Ports: []string{"any"},
					},
					Destination: Network{
						Nets:  []string{"$EXTERNAL_NET"},
						Ports: []string{"any"},
					},
					Description: "unsupported option key",
					Matchers: []orderedMatcher{
						&Content{
							Pattern: []byte("foo"),
						},
						&Content{
							Pattern: []byte("baz"),
						},
					},
					SID:      4321,
					Revision: 1,
				},
				Options: []string{"zibzab", "foobar"},
			},
		},
		{
			name: "test noalert",
			rule: `alert http any any -> any any (msg:"test noalert"; noalert; sid:1; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         1,
				Revision:    1,
				Description: "test noalert",
				Statements:  []string{"noalert"},
			},
		},
		{
			name: "test byte_math",
			rule: `alert tcp-pkt $HOME_NET any -> $EXTERNAL_NET any (msg:"test byte_math"; byte_math:bytes 4, offset 0,oper +,rvalue 6,result length,relative; isdataat:!length; sid:2; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp-pkt",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				SID:         2,
				Revision:    1,
				Description: "test byte_math",
				Matchers: []orderedMatcher{
					&ByteMatch{
						Kind:     bMath,
						NumBytes: "4",
						Offset:   "0",
						Operator: "+",
						Value:    "6",
						Variable: "length",
						Options:  []string{"relative"},
					},
					&ByteMatch{
						Kind:     isDataAt,
						NumBytes: "length",
						Negate:   true,
					},
				},
			},
		},
		{
			name: "test dsize lte",
			rule: `alert ip any any -> any any (msg:"test dsize lte"; dsize:<=500; sid:3; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "ip",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         3,
				Revision:    1,
				Description: "test dsize lte",
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     dSize,
						Num:      500,
						Operator: "<=",
					},
				},
			},
		},
		{
			name: "test dsize gte",
			rule: `alert ip any any -> any any (msg:"test dsize gte"; dsize:>=500; sid:4; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "ip",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         4,
				Revision:    1,
				Description: "test dsize gte",
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     dSize,
						Num:      500,
						Operator: ">=",
					},
				},
			},
		},
		{
			name: "test filesize",
			rule: `alert tcp any any -> any any (msg:"test filesize"; filesize:<10000; sid:5; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         5,
				Revision:    1,
				Description: "test filesize",
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     fileSize,
						Num:      10000,
						Operator: "<",
					},
				},
			},
		},
		{
			name: "test app-layer-event",
			rule: `alert tls any any -> any any (msg:"test app-layer-event"; app-layer-event:tls.invalid_record; sid:6; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tls",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         6,
				Revision:    1,
				Description: "test app-layer-event",
				Tags: map[string]string{
					"app-layer-event": "tls.invalid_record",
				},
			},
		},
		{
			name: "test decode-event",
			rule: `alert ip any any -> any any (msg:"test decode-event"; decode-event:ipv4.opt_eol; sid:7; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "ip",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         7,
				Revision:    1,
				Description: "test decode-event",
				Tags: map[string]string{
					"decode-event": "ipv4.opt_eol",
				},
			},
		},
		{
			name: "test snmp.version",
			rule: `alert snmp any any -> any any (msg:"test snmp.version"; snmp.version:<=2; sid:8; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "snmp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         8,
				Revision:    1,
				Description: "test snmp.version",
				Tags: map[string]string{
					"snmp.version": "<=2",
				},
			},
		},
		{
			name: "test stream-event",
			rule: `alert tcp any any -> any any (msg:"test stream-event"; stream-event:3way_handshake_wrong_seq; sid:9; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         9,
				Revision:    1,
				Description: "test stream-event",
				Tags: map[string]string{
					"stream-event": "3way_handshake_wrong_seq",
				},
			},
		},
		{
			name: "test engine-event",
			rule: `alert ip any any -> any any (msg:"test engine-event"; engine-event:event_id; sid:10; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "ip",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         10,
				Revision:    1,
				Description: "test engine-event",
				Tags: map[string]string{
					"engine-event": "event_id",
				},
			},
		},
		{
			name: "test ipv4.hdr",
			rule: `alert udp any any -> any any (msg:"test ipv4.hdr"; ipv4.hdr; byte_test:2,!&,0x1FFF,6,relative; sid:11; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "udp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         11,
				Revision:    1,
				Description: "test ipv4.hdr",
				Matchers: []orderedMatcher{
					&ByteMatch{
						Kind:         bTest,
						NumBytes:     "2",
						Operator:     "!&",
						Value:        "0x1FFF",
						Offset:       "6",
						Options:      []string{"relative"},
						DataPosition: ipv4Hdr,
					},
				},
			},
		},
		{
			name: "test dce_stub_data",
			rule: `alert tcp any any -> any 445 (msg:"test dce_stub_data"; dce_stub_data; content:"MZ"; sid:12; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"445"},
				},
				SID:         12,
				Revision:    1,
				Description: "test dce_stub_data",
				Matchers: []orderedMatcher{
					&Content{
						Pattern:      []byte("MZ"),
						DataPosition: dceStubData,
					},
				},
			},
		},
		{
			name: "test dnp3_func and dnp3_ind",
			rule: `alert tcp any any -> any any (msg:"test dnp3"; dnp3_func:13; dnp3_ind:no_func_code_support; sid:13; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         13,
				Revision:    1,
				Description: "test dnp3",
				Tags: map[string]string{
					"dnp3_func": "13",
					"dnp3_ind":  "no_func_code_support",
				},
			},
		},
		{
			name: "test krb5_err_code",
			rule: `alert krb5 any any -> any any (msg:"test krb5_err_code"; krb5_err_code:6; sid:14; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "krb5",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         14,
				Revision:    1,
				Description: "test krb5_err_code",
				Tags: map[string]string{
					"krb5_err_code": "6",
				},
			},
		},
		{
			name: "test dns.opcode",
			rule: `alert dns any any -> any any (msg:"test dns.opcode"; dns.opcode:0; sid:15; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "dns",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         15,
				Revision:    1,
				Description: "test dns.opcode",
				Tags: map[string]string{
					"dns.opcode": "0",
				},
			},
		},
		{
			name: "test protocols and checksums",
			rule: `alert igmp any any -> any any (msg:"test igmp"; igmp-csum:invalid; sid:16; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "igmp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         16,
				Revision:    1,
				Description: "test igmp",
				Tags: map[string]string{
					"igmp-csum": "invalid",
				},
			},
		},
		{
			name: "test ldap and pop3 and mdns and websocket",
			rule: `alert ldap any any -> any any (msg:"test ldap"; sid:17; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "ldap",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         17,
				Revision:    1,
				Description: "test ldap",
			},
		},
		{
			name: "test file options and filestore",
			rule: `alert http any any -> any any (msg:"test files"; fileext:"jpg"; filemagic:"PNG image"; filemd5:chksum.list; filestore; sid:18; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "http",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         18,
				Revision:    1,
				Description: "test files",
				Tags: map[string]string{
					"fileext":   "jpg",
					"filemagic": "PNG image",
					"filemd5":   "chksum.list",
				},
				Statements: []string{"filestore"},
			},
		},
		{
			name: "issue 89 - negated app-layer-protocol",
			rule: `alert tcp any any -> any 80 (msg:"SURICATA Port 80 but not HTTP"; flow:to_server; app-layer-protocol:!http; sid:2271002; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"80"},
				},
				SID:         2271002,
				Revision:    1,
				Description: "SURICATA Port 80 but not HTTP",
				Tags: map[string]string{
					"flow":               "to_server",
					"app-layer-protocol": "!http",
				},
			},
		},
		{
			name: "test whitespace around options",
			rule: `alert tcp $HOME_NET any -> any any ( msg:"test whitespace"; priority:3; sid:62000014; rev:1; )`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         62000014,
				Revision:    1,
				Description: "test whitespace",
				Tags: map[string]string{
					"priority": "3",
				},
			},
		},
		{
			name: "test lua and luajit keywords",
			rule: `alert tcp $HOME_NET any -> any any (msg:"test lua"; luajit:script.lua; lua:other.lua; sid:19; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         19,
				Revision:    1,
				Description: "test lua",
				Tags: map[string]string{
					"luajit": "script.lua",
					"lua":    "other.lua",
				},
			},
		},
		{
			name: "test threshold",
			rule: `alert tcp $HOME_NET any -> any any (msg:"test threshold"; threshold:type limit, track by_src, count 1, seconds 60; sid:20; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         20,
				Revision:    1,
				Description: "test threshold",
				Threshold: &Threshold{
					Type:    "limit",
					Track:   "by_src",
					Count:   1,
					Seconds: 60,
				},
			},
		},
		{
			name: "test detection_filter",
			rule: `alert tcp $HOME_NET any -> any any (msg:"test detection_filter"; detection_filter:track by_src, count 10, seconds 60, unique_on dst_port; sid:21; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         21,
				Revision:    1,
				Description: "test detection_filter",
				DetectionFilter: &DetectionFilter{
					Track:    "by_src",
					Count:    10,
					Seconds:  60,
					UniqueOn: "dst_port",
				},
			},
		},
		{
			name: "test target src_ip",
			rule: `alert tcp $HOME_NET any -> any any (msg:"test target src_ip"; target:src_ip; sid:22; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         22,
				Revision:    1,
				Description: "test target src_ip",
				Target:      "src_ip",
			},
		},
		{
			name: "test target dest_ip uppercase",
			rule: `alert tcp $HOME_NET any -> any any (msg:"test target dest_ip"; TARGET:DEST_IP; sid:23; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         23,
				Revision:    1,
				Description: "test target dest_ip",
				Target:      "dest_ip",
			},
		},
		{
			name:    "test invalid target",
			rule:    `alert tcp $HOME_NET any -> any any (msg:"test invalid target"; target:foo_bar; sid:24; rev:1;)`,
			wantErr: true,
		},
		{
			name: "test flowbits reset",
			rule: `alert tcp $HOME_NET any -> any any (msg:"test flowbits reset"; flowbits:reset; sid:25; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         25,
				Revision:    1,
				Description: "test flowbits reset",
				Flowbits: []*Flowbit{
					{
						Action: "reset",
					},
				},
			},
		},
		{
			name: "test flowbits uppercase SET",
			rule: `alert tcp $HOME_NET any -> any any (msg:"test flowbits uppercase"; FLOWBITS:SET,foo; sid:26; rev:1;)`,
			want: &Rule{
				Action:   "alert",
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"any"},
					Ports: []string{"any"},
				},
				SID:         26,
				Revision:    1,
				Description: "test flowbits uppercase",
				Flowbits: []*Flowbit{
					{
						Action: "set",
						Value:  "foo",
					},
				},
			},
		},
	} {
		got, err := ParseRule(tt.rule)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatalf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff)
		}
		// Validate UnsupportedOptionError contents.
		if uerr, ok := err.(*UnsupportedOptionError); ok {
			diff := pretty.Compare(uerr, tt.optErr)
			if diff != "" {
				t.Fatalf("%s: diff (-got +want)\n%s", tt.name, diff)
			}
		}
	}
}

func TestInSlice(t *testing.T) {
	for _, tt := range []struct {
		str  string
		strs []string
		want bool
	}{
		{
			str:  "pkt_data",
			strs: []string{"foo", "bar", "baze"},
			want: false,
		},
		{
			str:  "pkt_data",
			strs: []string{"foo", "pkt_data", "baze"},
			want: true,
		},
	} {
		got := inSlice(tt.str, tt.strs)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v", got, tt.want)
		}
	}
}

// Test that parsing a string input and then parsing the stringer output of that struct are identical.
func TestInEqualOut(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
	}{
		{
			name:  "simple test",
			input: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"|28|foo"; content:".AA"; within:40;)`,
		},
		{
			name:  "complex rule",
			input: `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"FOO BAR BLAH"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|3d 21 2d 2f|eyJjWEEEEEE"; fast_pattern; content:"|3z 21 2f 2d|"; pcre:"/^(?:[A-Z0-9+/]{1})*(?:[A-Z0-9+/]{1}==|[A-Z0-9+/]{7}=|[A-Z0-9+/]{9})/R"; metadata: former_category BOO; reference:url,this.is.sparta.com/fooblog; classtype:trojan-activity; sid:1111111; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag FOOO, signature_severity Major, created_at 2018_06_25, performance_impact Low, updated_at 2018_09_23;)`,
		},
	} {
		first, err := ParseRule(tt.input)
		if err != nil {
			t.Fatalf("%v", err)
		}
		second, err := ParseRule(first.String())
		if err != nil {
			t.Fatalf("%v", err)
		}
		diff := pretty.Compare(first, second)
		if diff != "" {
			t.Fatalf("%s: diff (-got +want):\n%s", tt.name, diff)
		}
	}
}
func TestContainsUnescaped(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "correctly escaped",
			input: `\\A\;B\"C\:`,
			want:  false,
		},
		{
			name:  "trailing slash",
			input: `\\A\;B\"C\:\`,
			want:  true,
		},
		{
			name:  "leading slash",
			input: `\ABC`,
			want:  true,
		},
		{
			name:  "even slashes",
			input: `\\\\\\\\`,
			want:  false,
		},
		{
			name:  "odd slashes",
			input: `\\\\\\\\\`,
			want:  true,
		},
		{
			name:  "even slashes semicolon",
			input: `\\\\\\\\;`,
			want:  true,
		},
		{
			name:  "odd slashes semicolon",
			input: `\\\\\\\\\;`,
			want:  false,
		},
		{
			name:  "escaped pipe",
			input: `\|`,
			want:  false,
		},
		{
			name:  "escaped bracket",
			input: `\[`,
			want:  false,
		},
		{
			name:  "escaped plus dot space",
			input: `\+\.\ `,
			want:  false,
		},
	} {
		got := containsUnescaped(tt.input)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v", got, tt.want)
		}
	}
}

func TestValidNetwork(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid",
			input: "192.100.10.1/28",
			want:  true,
		},
		{
			name:  "invalid address",
			input: "192.168.10",
			want:  false,
		},
		{
			name:  "invalid CIDR",
			input: "168.168.1.1/40",
			want:  false,
		},
	} {
		got := validNetwork(tt.input)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v:\n%s", got, tt.want, tt.name)
		}
	}
}

func TestPortsValid(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input []string
		want  bool
	}{
		{
			name:  "valid port",
			input: []string{"8080", "1"},
			want:  true,
		},
		{
			name:  "nested range",
			input: []string{"1:80", "![2,4]"},
			want:  true,
		},
		{
			name:  "nested range",
			input: []string{"![25,110,143,465,587,2525]"},
			want:  true,
		},
		{
			name:  "port list",
			input: []string{"[443,465,993,995,25]"},
			want:  true,
		},
		{
			name:  "open upper range",
			input: []string{"[1024:]"},
			want:  true,
		},
		{
			name:  "invalid port",
			input: []string{"8080", "87236423"},
			want:  false,
		},
	} {
		got := portsValid(tt.input)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v:\n%s", got, tt.want, tt.name)
		}
	}
}

func TestValidNetworks(t *testing.T) {
	for _, tt := range []struct {
		name string
		strs []string
		want bool
	}{
		{
			name: "all valid",
			strs: []string{"192.168.1.1/31", "$FOOBAR", "!192.168.10.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			want: true,
		},
		{
			name: "double negation",
			strs: []string{"192.168.1.1/31", "$FOOBAR", "!!192.168.10.1"},
			want: false,
		},
		{
			name: "invalid variable",
			strs: []string{"192.168.1.1/31", "FOOBAR", "!192.168.10.1"},
			want: false,
		},
		{
			name: "invalid CIDR",
			strs: []string{"192.168.1.1/37", "$FOOBAR", "!192.168.10.1"},
			want: false,
		},
	} {
		got := validNetworks(tt.strs)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v:\n%s", got, tt.want, tt.name)
		}
	}
}

func TestParseRules(t *testing.T) {
	input := `# Rules file
alert tcp any any -> any any (msg:"rule 1"; sid:1; rev:1;)
alert udp any any -> any any (msg:"rule 2"; sid:2; rev:1;)
`
	rules, err := ParseRules(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseRules unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("ParseRules got %d rules, expected 2", len(rules))
	}
	if rules[0].SID != 1 || rules[1].SID != 2 {
		t.Errorf("rules SIDs mismatch: %d, %d", rules[0].SID, rules[1].SID)
	}
}

func TestParseRuleConcurrent(t *testing.T) {
	rules := []struct {
		rule       string
		want       DataPos
		transforms int
	}{
		{
			rule:       `alert http any any -> any any (msg:"sticky buffer"; http.uri; to_lowercase; content:"a"; sid:1; rev:1;)`,
			want:       httpURI,
			transforms: 1,
		},
		{
			rule: `alert tcp any any -> any any (msg:"pkt data"; content:"b"; sid:2; rev:1;)`,
			want: pktData,
		},
	}
	var wg sync.WaitGroup
	for _, tt := range rules {
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(rule string, want DataPos, transforms int) {
				defer wg.Done()
				for i := 0; i < 100; i++ {
					r, err := ParseRule(rule)
					if err != nil {
						t.Errorf("ParseRule unexpected error: %v", err)
						return
					}
					c := r.Contents()[0]
					if c.DataPosition != want || len(c.Transforms) != transforms {
						t.Errorf("got DataPosition=%v with %d transforms; want %v with %d", c.DataPosition, len(c.Transforms), want, transforms)
						return
					}
				}
			}(tt.rule, tt.want, tt.transforms)
		}
	}
	wg.Wait()
}

func TestParseRuleTransformsNoAliasing(t *testing.T) {
	ruleStr := `alert http any any -> any any (msg:"aliasing test"; http.uri; to_lowercase; url_decode; content:"a"; dotprefix; content:"b"; pcre:"/c/"; sid:1; rev:1;)`
	r, err := ParseRule(ruleStr)
	if err != nil {
		t.Fatalf("ParseRule unexpected error: %v", err)
	}

	contents := r.Contents()
	if len(contents) != 2 {
		t.Fatalf("got %d contents; want 2", len(contents))
	}
	pcres := r.PCREs()
	if len(pcres) != 1 {
		t.Fatalf("got %d pcres; want 1", len(pcres))
	}

	// Verify mutating a Transform struct on the first Content does not mutate sibling Content or PCRE matchers.
	contents[0].Transforms[0].Name = "to_uppercase"
	if got := contents[1].Transforms[0].Name; got != "to_lowercase" {
		t.Errorf("contents[1].Transforms[0].Name = %q; want %q (pointer aliasing detected)", got, "to_lowercase")
	}
	if got := pcres[0].Transforms[0].Name; got != "to_lowercase" {
		t.Errorf("pcres[0].Transforms[0].Name = %q; want %q (pointer aliasing detected)", got, "to_lowercase")
	}

	// Verify appending to the first Content's Transforms slice does not overwrite the backing array of sibling matchers.
	contents[0].Transforms = append(contents[0].Transforms, &Transform{Name: "strip_whitespace"})
	if got := contents[1].Transforms[2].Name; got != "dotprefix" {
		t.Errorf("contents[1].Transforms[2].Name = %q; want %q (slice backing array aliasing detected)", got, "dotprefix")
	}
	if got := pcres[0].Transforms[2].Name; got != "dotprefix" {
		t.Errorf("pcres[0].Transforms[2].Name = %q; want %q (slice backing array aliasing detected)", got, "dotprefix")
	}
}

func TestParseDatasetAndDataRep(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rule    string
		want    *Rule
		wantErr bool
	}{
		{
			name: "dataset with sticky buffer and transform (no content)",
			rule: `alert dns any any -> any any (msg:"blocked dns"; dns.query; to_lowercase; dataset:isset,malware,type string,load datasets/malware.txt; sid:12001201; rev:1;)`,
			want: &Rule{
				Action:      "alert",
				Protocol:    "dns",
				Source:      Network{Nets: []string{"any"}, Ports: []string{"any"}},
				Destination: Network{Nets: []string{"any"}, Ports: []string{"any"}},
				Description: "blocked dns",
				Matchers: []orderedMatcher{
					&Dataset{
						DataPosition: dnsQuery5,
						Transforms: []*Transform{
							{Name: "to_lowercase"},
						},
						Cmd:     "isset",
						Name:    "malware",
						Options: []string{"type string", "load datasets/malware.txt"},
					},
				},
				SID:      12001201,
				Revision: 1,
			},
		},
		{
			name: "dataset following content on sticky buffer",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"chrome version"; http.user_agent; content:"Chrome/"; dataset:isnotset,pawpatrules_chrome_l,type string,load pawpatrules_chrome_l.lst; sid:3321369; rev:2;)`,
			want: &Rule{
				Action:      "alert",
				Protocol:    "http",
				Source:      Network{Nets: []string{"$HOME_NET"}, Ports: []string{"any"}},
				Destination: Network{Nets: []string{"$EXTERNAL_NET"}, Ports: []string{"any"}},
				Description: "chrome version",
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpUserAgent,
						Pattern:      []byte("Chrome/"),
					},
					&Dataset{
						DataPosition: httpUserAgent,
						Cmd:          "isnotset",
						Name:         "pawpatrules_chrome_l",
						Options:      []string{"type string", "load pawpatrules_chrome_l.lst"},
					},
				},
				SID:      3321369,
				Revision: 2,
			},
		},
		{
			name: "datarep with sticky buffer",
			rule: `alert dns any any -> any any (msg:"datarep dns"; dns.query; datarep:bad_domains,>,10,load bad_domains.rep,type string; sid:12001202; rev:1;)`,
			want: &Rule{
				Action:      "alert",
				Protocol:    "dns",
				Source:      Network{Nets: []string{"any"}, Ports: []string{"any"}},
				Destination: Network{Nets: []string{"any"}, Ports: []string{"any"}},
				Description: "datarep dns",
				Matchers: []orderedMatcher{
					&DataRep{
						DataPosition: dnsQuery5,
						Name:         "bad_domains",
						Operator:     ">",
						Value:        10,
						Options:      []string{"load bad_domains.rep", "type string"},
					},
				},
				SID:      12001202,
				Revision: 1,
			},
		},
		{
			name:    "dataset invalid command",
			rule:    `alert dns any any -> any any (msg:"bad cmd"; dns.query; dataset:invalidcmd,malware; sid:1; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "dataset missing name",
			rule:    `alert dns any any -> any any (msg:"missing name"; dns.query; dataset:isset; sid:1; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "dataset empty name",
			rule:    `alert dns any any -> any any (msg:"empty name"; dns.query; dataset:isset,; sid:1; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "datarep invalid operator",
			rule:    `alert dns any any -> any any (msg:"bad op"; dns.query; datarep:bad_domains,~,10; sid:1; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "datarep non-integer value",
			rule:    `alert dns any any -> any any (msg:"bad val"; dns.query; datarep:bad_domains,>,abc; sid:1; rev:1;)`,
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRule(%q) error = %v, wantErr %v", tt.rule, err, tt.wantErr)
			}
			if !tt.wantErr {
				if diff := pretty.Compare(got, tt.want); diff != "" {
					t.Errorf("ParseRule(%q) diff (-got +want):\n%s", tt.rule, diff)
				}
			}
		})
	}
}

func TestParseSuri8Transforms(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule string
		want []*Transform
	}{
		{
			name: "domain transform",
			rule: `alert dns any any -> any any (msg:"domain transform"; dns.query; domain; dataset:isset,malware,type string,load datasets/malware.txt; sid:12001201; rev:1;)`,
			want: []*Transform{{Name: "domain"}},
		},
		{
			name: "tld transform",
			rule: `alert dns any any -> any any (msg:"tld transform"; dns.query; tld; content:"com"; sid:12001202; rev:1;)`,
			want: []*Transform{{Name: "tld"}},
		},
		{
			name: "from_base64 bare transform",
			rule: `alert http any any -> any any (msg:"from_base64 bare"; http.uri; from_base64; content:"admin"; sid:12001203; rev:1;)`,
			want: []*Transform{{Name: "from_base64"}},
		},
		{
			name: "from_base64 parameterized transform",
			rule: `alert http any any -> any any (msg:"from_base64 params"; http.uri; from_base64:bytes 4, offset 2, mode rfc4648; content:"admin"; sid:12001204; rev:1;)`,
			want: []*Transform{{Name: "from_base64", Value: "bytes 4, offset 2, mode rfc4648"}},
		},
		{
			name: "luaxform transform",
			rule: `alert http any any -> any any (msg:"luaxform"; http.uri; luaxform:decode.lua, offset 0, bytes 16; content:"admin"; sid:12001205; rev:1;)`,
			want: []*Transform{{Name: "luaxform", Value: "decode.lua, offset 0, bytes 16"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.rule)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", tt.rule, err)
			}
			var gotTransforms []*Transform
			if len(got.Contents()) > 0 {
				gotTransforms = got.Contents()[0].Transforms
			} else if len(got.Datasets()) > 0 {
				gotTransforms = got.Datasets()[0].Transforms
			}
			if diff := pretty.Compare(gotTransforms, tt.want); diff != "" {
				t.Errorf("transforms diff (-got +want):\n%s", diff)
			}
			if gotStr := got.String(); gotStr != tt.rule {
				t.Errorf("got.String() = %q; want %q", gotStr, tt.rule)
			}
		})
	}
}

func TestParseSuri8StickyBuffers(t *testing.T) {
	buffers := []string{
		"quic.sni",
		"quic.version",
		"quic.cyu.hash",
		"quic.cyu.string",
		"quic.ua",
		"ja4.hash",
		"ja4.raw",
		"ja4s.hash",
		"ja4s.raw",
		"ssh.hassh",
		"ssh.hassh.string",
		"ssh.hassh.server",
		"ssh.hassh.server.string",
		"snmp.community",
		"snmp.pdu_type",
		"ip.src",
		"ip.dst",
		"http2.frametype",
		"http2.errorcode",
		"http2.priority",
		"http2.window",
		"http2.size_update",
		"http2.settings",
		"http2.header",
		"http2.header_name",
		"http2.header_value",
	}
	for _, buf := range buffers {
		t.Run(buf, func(t *testing.T) {
			ruleStr := `alert ip any any -> any any (msg:"test ` + buf + `"; ` + buf + `; content:"test"; sid:1; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if len(got.Contents()) != 1 {
				t.Fatalf("got %d contents; want 1", len(got.Contents()))
			}
			if gotBuf := got.Contents()[0].DataPosition.String(); gotBuf != buf {
				t.Errorf("got DataPosition.String() = %q; want %q", gotBuf, buf)
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}
}

func TestParseRequires(t *testing.T) {
	for _, tt := range []struct {
		name     string
		rule     string
		want     *Requires
		wantRule string
		wantErr  bool
	}{
		{
			name: "simple version",
			rule: `alert http any any -> any any (msg:"test requires"; content:"foo"; requires:version >= 8; sid:1; rev:1;)`,
			want: &Requires{
				Version: [][]VersionConstraint{
					{
						{Operator: ">=", Version: "8"},
					},
				},
			},
			wantRule: `alert http any any -> any any (msg:"test requires"; content:"foo"; requires:version >= 8; sid:1; rev:1;)`,
		},
		{
			name: "ranged AND version",
			rule: `alert http any any -> any any (msg:"test requires range"; content:"foo"; requires:version >= 7.0.4 < 8; sid:2; rev:1;)`,
			want: &Requires{
				Version: [][]VersionConstraint{
					{
						{Operator: ">=", Version: "7.0.4"},
						{Operator: "<", Version: "8"},
					},
				},
			},
			wantRule: `alert http any any -> any any (msg:"test requires range"; content:"foo"; requires:version >= 7.0.4 < 8; sid:2; rev:1;)`,
		},
		{
			name: "compound OR and AND version with feature and keyword",
			rule: `alert tls any any -> any any (msg:"test compound requires"; ja4.hash; content:"t13d"; requires:version >= 7.0.4 < 8 | >= 8.0.3, feature geoip, keyword bar; sid:3; rev:1;)`,
			want: &Requires{
				Version: [][]VersionConstraint{
					{
						{Operator: ">=", Version: "7.0.4"},
						{Operator: "<", Version: "8"},
					},
					{
						{Operator: ">=", Version: "8.0.3"},
					},
				},
				Features: []string{"geoip"},
				Keywords: []string{"bar"},
			},
			wantRule: `alert tls any any -> any any (msg:"test compound requires"; ja4.hash; content:"t13d"; requires:version >= 7.0.4 < 8 | >= 8.0.3, feature geoip, keyword bar; sid:3; rev:1;)`,
		},
		{
			name:    "duplicate version error",
			rule:    `alert http any any -> any any (msg:"dup version"; content:"foo"; requires:version >= 7, version >= 8; sid:4; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "invalid version operator",
			rule:    `alert http any any -> any any (msg:"bad op"; content:"foo"; requires:version ~= 8; sid:5; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "invalid version number",
			rule:    `alert http any any -> any any (msg:"bad ver"; content:"foo"; requires:version >= 8.x.1; sid:6; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "unknown requires sub-key",
			rule:    `alert http any any -> any any (msg:"bad key"; content:"foo"; requires:unknown foo; sid:7; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "empty feature value",
			rule:    `alert http any any -> any any (msg:"empty feature"; content:"foo"; requires:feature; sid:8; rev:1;)`,
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRule(%q) error = %v, wantErr %v", tt.rule, err, tt.wantErr)
			}
			if !tt.wantErr {
				if diff := pretty.Compare(got.Requires, tt.want); diff != "" {
					t.Errorf("Requires diff (-got +want):\n%s", diff)
				}
				if gotStr := got.String(); gotStr != tt.wantRule {
					t.Errorf("got.String() = %q; want %q", gotStr, tt.wantRule)
				}
			}
		})
	}
}

func TestParseSuri8LenMatchersAndTLS(t *testing.T) {
	lenKeywords := []string{
		"flow.bytes_toserver",
		"flow.bytes_toclient",
		"flow.pkts_toserver",
		"flow.pkts_toclient",
		"flow.age",
		"flow.pkts",
		"flow.bytes",
		"tcp.mss",
		"tcp.wscale",
	}
	for _, kw := range lenKeywords {
		t.Run(kw, func(t *testing.T) {
			ruleStr := `alert tcp any any -> any any (msg:"test ` + kw + `"; ` + kw + `:>=1460; sid:1; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if len(got.LenMatchers()) != 1 {
				t.Fatalf("got %d LenMatchers; want 1", len(got.LenMatchers()))
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}

	tlsStmts := []string{
		"tls_cert_expired",
		"tls_cert_valid",
		"tls.cert_expired",
		"tls.cert_valid",
	}
	for _, stmt := range tlsStmts {
		t.Run(stmt, func(t *testing.T) {
			ruleStr := `alert tls any any -> any any (msg:"test ` + stmt + `"; ` + stmt + `; sid:2; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}

	tlsCertTags := []string{
		"tls_cert_notbefore",
		"tls_cert_notafter",
		"tls.cert_notbefore",
		"tls.cert_notafter",
	}
	for _, tag := range tlsCertTags {
		t.Run(tag, func(t *testing.T) {
			ruleStr := `alert tls any any -> any any (msg:"test ` + tag + `"; ` + tag + `:2025-01-01; sid:3; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}
}

func TestParseDCERPCAndPrefilter(t *testing.T) {
	t.Run("dcerpc.iface, dcerpc.opnum, and dcerpc.stub_data", func(t *testing.T) {
		ruleStr := `alert smb any any -> $HOME_NET any (msg:"test dcerpc"; flow:to_server, established; dcerpc.stub_data; content:"foo"; dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003; dcerpc.opnum:12; sid:3115102; rev:4;)`
		got, err := ParseRule(ruleStr)
		if err != nil {
			t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
		}
		if got.Tags["dcerpc.iface"] != "367abb81-9844-35f1-ad32-98f038001003" {
			t.Errorf("got dcerpc.iface = %q; want %q", got.Tags["dcerpc.iface"], "367abb81-9844-35f1-ad32-98f038001003")
		}
		if got.Tags["dcerpc.opnum"] != "12" {
			t.Errorf("got dcerpc.opnum = %q; want %q", got.Tags["dcerpc.opnum"], "12")
		}
		if len(got.Contents()) != 1 || got.Contents()[0].DataPosition.String() != "dcerpc.stub_data" {
			t.Errorf("got DataPosition = %v; want dcerpc.stub_data", got.Contents())
		}
	})

	t.Run("prefilter statement", func(t *testing.T) {
		ruleStr := `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"test prefilter"; dsize:>512; content:"foo"; prefilter; sid:2610454; rev:1;)`
		got, err := ParseRule(ruleStr)
		if err != nil {
			t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
		}
		if gotStr := got.String(); gotStr != ruleStr {
			t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
		}
	})
}

func TestParseSuricataActions(t *testing.T) {
	actions := []string{
		"alert",
		"drop",
		"pass",
		"reject",
		"rejectsrc",
		"rejectdst",
		"rejectboth",
		"config",
	}
	for _, action := range actions {
		t.Run("action_"+action, func(t *testing.T) {
			ruleStr := action + ` dns any any -> any any (msg:"test ` + action + `"; dns.query; content:"suricata"; sid:1; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if got.Action != action {
				t.Errorf("got.Action = %q; want %q", got.Action, action)
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}

	t.Run("invalid_action", func(t *testing.T) {
		ruleStr := `accept dns any any -> any any (msg:"invalid action"; sid:1; rev:1;)`
		if _, err := ParseRule(ruleStr); err == nil {
			t.Fatalf("ParseRule(%q) expected error, got nil", ruleStr)
		}
	})
}

func TestParseSuricataDirections(t *testing.T) {
	for _, tt := range []struct {
		dir               string
		wantBidirectional bool
		wantTransactional bool
	}{
		{dir: "->", wantBidirectional: false, wantTransactional: false},
		{dir: "<>", wantBidirectional: true, wantTransactional: false},
		{dir: "=>", wantBidirectional: false, wantTransactional: true},
	} {
		t.Run("direction_"+tt.dir, func(t *testing.T) {
			ruleStr := `alert http any any ` + tt.dir + ` 5.6.7.8 80 (msg:"matching both uri and status"; http.uri; content:"/download"; http.stat_code; content:"200"; sid:1; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if got.Bidirectional != tt.wantBidirectional {
				t.Errorf("got.Bidirectional = %v; want %v", got.Bidirectional, tt.wantBidirectional)
			}
			if got.Transactional != tt.wantTransactional {
				t.Errorf("got.Transactional = %v; want %v", got.Transactional, tt.wantTransactional)
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}

	for _, badDir := range []string{"<-", "<=", "==>"} {
		t.Run("invalid_direction_"+badDir, func(t *testing.T) {
			ruleStr := `alert http any any ` + badDir + ` 5.6.7.8 80 (msg:"bad dir"; sid:1; rev:1;)`
			if _, err := ParseRule(ruleStr); err == nil {
				t.Fatalf("ParseRule(%q) expected error, got nil", ruleStr)
			}
		})
	}
}

func TestParseDecompressionTransforms(t *testing.T) {
	for _, tt := range []struct {
		name     string
		rule     string
		wantName string
		wantVal  string
	}{
		{
			name:     "gunzip_bare",
			rule:     `alert http any any -> any any (msg:"test gunzip"; file.data; gunzip; content:"test"; sid:1; rev:1;)`,
			wantName: "gunzip",
			wantVal:  "",
		},
		{
			name:     "gunzip_max_size",
			rule:     `alert http any any -> any any (msg:"test gunzip max-size"; file.data; gunzip:max-size 1024; content:"test"; sid:2; rev:1;)`,
			wantName: "gunzip",
			wantVal:  "max-size 1024",
		},
		{
			name:     "zlib_deflate_bare",
			rule:     `alert http any any -> any any (msg:"test zlib_deflate"; file.data; zlib_deflate; content:"test"; sid:3; rev:1;)`,
			wantName: "zlib_deflate",
			wantVal:  "",
		},
		{
			name:     "zlib_deflate_max_size",
			rule:     `alert http any any -> any any (msg:"test zlib_deflate max-size"; file.data; zlib_deflate:max-size 1024; content:"test"; sid:4; rev:1;)`,
			wantName: "zlib_deflate",
			wantVal:  "max-size 1024",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.rule)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", tt.rule, err)
			}
			if len(got.Contents()) != 1 || len(got.Contents()[0].Transforms) != 1 {
				t.Fatalf("got Transforms = %v; want 1 transform", got.Contents())
			}
			tr := got.Contents()[0].Transforms[0]
			if tr.Name != tt.wantName || tr.Value != tt.wantVal {
				t.Errorf("got Transform = %+v; want Name=%q Value=%q", tr, tt.wantName, tt.wantVal)
			}
			if gotStr := got.String(); gotStr != tt.rule {
				t.Errorf("got.String() = %q; want %q", gotStr, tt.rule)
			}
		})
	}
}

func TestParseFrameStickyBuffers(t *testing.T) {
	for _, frameName := range []string{
		"dns.pdu",
		"ssh.record.hdr",
		"smtp.command_line",
		"smtp.response_line",
		"smtp.data",
		"smtp.stream",
		"http2.hdr",
		"future.custom_frame",
	} {
		t.Run("frame_"+frameName, func(t *testing.T) {
			ruleStr := `alert tcp any any -> any any (msg:"test frame ` + frameName + `"; frame:` + frameName + `; content:"foo"; sid:1; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if len(got.Contents()) != 1 {
				t.Fatalf("got %d contents; want 1", len(got.Contents()))
			}
			if got.Contents()[0].DataPosition.String() != "frame" {
				t.Errorf("got DataPosition = %q; want %q", got.Contents()[0].DataPosition.String(), "frame")
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}

	t.Run("multiple_frames_in_one_rule", func(t *testing.T) {
		ruleStr := `alert smtp any any => any any (msg:"multiple frames"; frame:smtp.command_line; content:"MAIL FROM"; bsize:>10; frame:smtp.response_line; pcre:"/^250 /"; sid:10; rev:1;)`
		got, err := ParseRule(ruleStr)
		if err != nil {
			t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
		}
		if gotStr := got.String(); gotStr != ruleStr {
			t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
		}
	})

	t.Run("empty_frame_error", func(t *testing.T) {
		for _, ruleStr := range []string{
			`alert tcp any any -> any any (msg:"empty frame"; frame; content:"foo"; sid:11; rev:1;)`,
			`alert tcp any any -> any any (msg:"empty string frame"; frame:""; content:"foo"; sid:12; rev:1;)`,
		} {
			_, err := ParseRule(ruleStr)
			if err == nil {
				t.Fatalf("ParseRule(%q) expected error, got nil", ruleStr)
			}
			if _, ok := err.(*UnsupportedOptionError); ok {
				t.Fatalf("ParseRule(%q) returned UnsupportedOptionError %v, expected validation error", ruleStr, err)
			}
		}
	})
}

func TestParseDirectionalStickyBuffers(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rule    string
		wantErr bool
	}{
		{
			name: "http_content_type_to_server_and_to_client",
			rule: `alert http any any => 5.6.7.8 80 (msg:"matching json to server and xml to client"; http.content_type:to_server; content:"json"; http.content_type:to_client; content:"xml"; sid:1; rev:1;)`,
		},
		{
			name: "file_data_to_server",
			rule: `alert smb any any => any any (msg:"directional file.data"; file.data:to_server; content:"MZ"; sid:2; rev:1;)`,
		},
		{
			name:    "invalid_sticky_direction",
			rule:    `alert http any any => any any (msg:"bad sticky dir"; http.uri:invalid_dir; content:"/test"; sid:3; rev:1;)`,
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRule(%q) error = %v, wantErr %v", tt.rule, err, tt.wantErr)
			}
			if !tt.wantErr {
				if gotStr := got.String(); gotStr != tt.rule {
					t.Errorf("got.String() = %q; want %q", gotStr, tt.rule)
				}
			}
		})
	}
}

func TestParseBypassAndAlertStatements(t *testing.T) {
	for _, stmt := range []string{"bypass", "alert"} {
		t.Run("statement_"+stmt, func(t *testing.T) {
			ruleStr := `alert tcp any any -> any any (msg:"test ` + stmt + `"; content:"foo"; ` + stmt + `; sid:1; rev:1;)`
			got, err := ParseRule(ruleStr)
			if err != nil {
				t.Fatalf("ParseRule(%q) unexpected error: %v", ruleStr, err)
			}
			if len(got.Statements) != 1 || got.Statements[0] != stmt {
				t.Errorf("got.Statements = %v; want [%q]", got.Statements, stmt)
			}
			if gotStr := got.String(); gotStr != ruleStr {
				t.Errorf("got.String() = %q; want %q", gotStr, ruleStr)
			}
		})
	}
}

func TestParseAbsent(t *testing.T) {
	for _, tt := range []struct {
		name       string
		rule       string
		wantOrElse bool
		wantErr    bool
	}{
		{
			name:       "absent_bare",
			rule:       `alert http any any -> any any (msg:"HTTP request without User-Agent"; http.user_agent; absent; sid:1; rev:1;)`,
			wantOrElse: false,
		},
		{
			name:       "absent_or_else",
			rule:       `alert http any any -> any any (msg:"HTTP user-agent absent or matching"; http.user_agent; absent:or_else; content:"curl"; sid:2; rev:1;)`,
			wantOrElse: true,
		},
		{
			name:    "absent_invalid_value",
			rule:    `alert http any any -> any any (msg:"invalid absent"; http.user_agent; absent:invalid; sid:3; rev:1;)`,
			wantErr: true,
		},
		{
			name:    "absent_string_value_error",
			rule:    `alert http any any -> any any (msg:"string absent"; http.user_agent; absent:"or_else"; sid:4; rev:1;)`,
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRule(%q) error = %v, wantErr %v", tt.rule, err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(got.Absents()) != 1 {
					t.Fatalf("len(got.Absents()) = %d; want 1", len(got.Absents()))
				}
				if got.Absents()[0].OrElse != tt.wantOrElse {
					t.Errorf("got.Absents()[0].OrElse = %v; want %v", got.Absents()[0].OrElse, tt.wantOrElse)
				}
				if gotStr := got.String(); gotStr != tt.rule {
					t.Errorf("got.String() = %q; want %q", gotStr, tt.rule)
				}
			}
		})
	}
}
