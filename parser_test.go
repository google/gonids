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
	"fmt"
	"reflect"
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
			t.Fatal(fmt.Sprintf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff))
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
				Variable: "Certs.len",
				Options:  []string{"relative", "little"},
			},
		},
		{
			name:  "basic byte_jump",
			input: "3,0",
			kind:  bJump,
			want: &ByteMatch{
				Kind:     bJump,
				NumBytes: "3",
				Offset:   0,
			},
		},
		{
			name:  "byte_jump with options",
			input: "3,0, relative, little",
			kind:  bJump,
			want: &ByteMatch{
				Kind:     bJump,
				NumBytes: "3",
				Offset:   0,
				Options:  []string{"relative", "little"},
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
				Offset:   0,
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
				Offset:   1,
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
			t.Fatal(fmt.Sprintf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff))
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
				Offset: 4,
			},
		},
		{
			name:  "random",
			input: "  relative,  offset  4, bytes     5",
			kind:  b64Decode,
			want: &ByteMatch{
				Kind:     b64Decode,
				NumBytes: "5",
				Offset:   4,
				Options:  []string{"relative"},
			},
		},
	} {
		got, err := parseBase64Decode(tt.kind, tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatal(fmt.Sprintf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff))
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
	} {
		got, err := parseFlowbit(tt.input)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatal(fmt.Sprintf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff))
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
			t.Fatal(fmt.Sprintf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff))
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
			t.Fatal(fmt.Sprintf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff))
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
			rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"VRT BLACKLIST URI request for known malicious URI - /tongji.js"; flow:to_server,established; content:"/tongji.js"; fast_pattern:only; http_uri; content:"Host|3A| "; http_header; pcre:"/Host\x3a[^\r\n]*?\.tongji/Hi"; metadata:impact_flag red, policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,labs.snort.org/docs/17904.html; classtype:trojan-activity; sid:17904; rev:6;)`,
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
				Description: "VRT BLACKLIST URI request for known malicious URI - /tongji.js",
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
						Offset:   0,
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
						Offset:   0,
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
						Offset:   3,
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
						Offset:   17,
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
			name: "content with backslash at end",
			rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ending backslash rule"; content:"foo\"; sid:12345; rev:2;)`, want: &Rule{
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
				Revision:    2,
				Description: "ending backslash rule",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte{0x66, 0x6f, 0x6f, 0x5c},
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
		// Errors
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
			name:    "network with space",
			rule:    `alert tcp $EXTERNAL_NET 443 -> $HOME_NET [123, 234] (msg:"bad network definition"; sid:4321;)`,
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
	} {
		got, err := ParseRule(tt.rule)
		diff := pretty.Compare(got, tt.want)
		if diff != "" || (err != nil) != tt.wantErr {
			t.Fatal(fmt.Sprintf("%s: gotErr:%#v, wantErr:%#v\n diff (-got +want):\n%s", tt.name, err, tt.wantErr, diff))
		}
		// Validate UnsupportedOptionError contents.
		if uerr, ok := err.(*UnsupportedOptionError); ok {
			diff := pretty.Compare(uerr, tt.optErr)
			if diff != "" {
				t.Fatal(fmt.Sprintf("%s: diff (-got +want)\n%s", tt.name, diff))
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
			t.Fatal(fmt.Sprintf("%s: diff (-got +want):\n%s", tt.name, diff))
		}
	}
}
