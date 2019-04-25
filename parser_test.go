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
	"testing"

	"github.com/davecgh/go-spew/spew"
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
			name:  "escaped content",
			input: `abcd\;ef`,
			want:  []byte("abcd;ef"),
		},
		{
			name:  "hex content",
			input: "A|42 43|D| 45|",
			want:  []byte("ABCDE"),
		},
	} {
		got, err := parseContent(tt.input)
		if !reflect.DeepEqual(got, tt.want) || (err != nil) != tt.wantErr {
			t.Fatalf("%s: got %v,%v; expected %v,%v", tt.name, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestContentToRegexp(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *Content
		want    string
		wantErr bool
	}{
		{
			name: "simple content",
			input: &Content{
				Pattern: []byte("abcd"),
			},
			want: `abcd`,
		},
		{
			name: "escaped content",
			input: &Content{
				Pattern: []byte("abcd;ef"),
			},
			want: `abcd;ef`,
		},
		{
			name: "complex escaped content",
			input: &Content{
				Pattern: []byte("abcd;:\r\ne\rf"),
			},
			want: `abcd;:\.\.e\.f`,
		},
	} {
		got := tt.input.ToRegexp()
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%s: got %v; expected %v", tt.name, got, tt.want)
		}
	}
}

func TestContentFormatPattern(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *Content
		want    string
		wantErr bool
	}{
		{
			name: "simple content",
			input: &Content{
				Pattern: []byte("abcd"),
			},
			want: "abcd",
		},
		{
			name: "escaped content",
			input: &Content{
				Pattern: []byte("abcd;ef"),
			},
			want: "abcd|3B|ef",
		},
		{
			name: "complex escaped content",
			input: &Content{
				Pattern: []byte("abcd;:\r\ne\rf"),
			},
			want: "abcd|3B 3A 0D 0A|e|0D|f",
		},
	} {
		got := tt.input.FormatPattern()
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%s: got %v; expected %v", tt.name, got, tt.want)
		}
	}
}

func TestFastPatternString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input FastPattern
		want  string
	}{
		{
			name: "fast_pattern",
			input: FastPattern{
				Enabled: true,
			},
			want: "fast_pattern;",
		},
		{
			name: "fast_pattern:only;",
			input: FastPattern{
				Enabled: true,
				Only:    true,
			},
			want: "fast_pattern:only;",
		},
		{
			name: "fast_pattern:`chop`",
			input: FastPattern{
				Enabled: true,
				Offset:  2,
				Length:  5,
			},
			want: "fast_pattern:2,5;",
		},
		{
			name: "invalid state",
			input: FastPattern{
				Enabled: true,
				Only:    true,
				Offset:  2,
				Length:  5,
			},
			want: "",
		},
		{
			name: "not enabled",
			input: FastPattern{
				Only:   true,
				Offset: 2,
				Length: 5,
			},
			want: "",
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v; expected %v", tt.name, got, tt.want)
		}
	}
}

func TestContentOptionString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input ContentOption
		want  string
	}{
		{
			name: "no value",
			input: ContentOption{
				Name: "http_uri",
			},
			want: "http_uri;",
		},
		{
			name: "value",
			input: ContentOption{
				Name:  "depth",
				Value: 0,
			},
			want: "depth:0;",
		},
		{
			name: "invalid value",
			input: ContentOption{
				Name:  "http_uri",
				Value: 1,
			},
			want: "http_uri;",
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v; expected %v", tt.name, got, tt.want)
		}
	}
}

func TestReferenceString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Reference
		want  string
	}{
		{
			name: "url",
			input: Reference{
				Type:  "url",
				Value: "www.google.com",
			},
			want: "reference:url,www.google.com;",
		},
		{
			name: "md5",
			input: Reference{
				Type:  "md5",
				Value: "2aee1c40199c7754da766e61452612cc",
			},
			want: "reference:md5,2aee1c40199c7754da766e61452612cc;",
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v; expected %v", tt.name, got, tt.want)
		}
	}
}

func TestMetdatasString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Metadatas
		want  string
	}{
		{
			name: "one meta",
			input: Metadatas{
				&Metadata{
					Key:   "foo",
					Value: "bar",
				},
			},
			want: "metadata:foo bar;",
		},
		{
			name: "three meta",
			input: Metadatas{
				&Metadata{
					Key:   "created_at",
					Value: "2019_01_01",
				},
				&Metadata{
					Key:   "updated_at",
					Value: "2019_01_07",
				},
				&Metadata{
					Key:   "target",
					Value: "Windows",
				},
			},
			want: "metadata:created_at 2019_01_01, updated_at 2019_01_07, target Windows;",
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestNetString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "one net",
			input: []string{"$HOME_NET"},
			want:  "$HOME_NET",
		},
		{
			name:  "three nets",
			input: []string{"$HOME_NET", "!$FOO_NET", "192.168.0.0/16"},
			want:  "[$HOME_NET, !$FOO_NET, 192.168.0.0/16]",
		},
	} {
		got := netString(tt.input)
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestNetworkString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Network
		want  string
	}{
		{
			name: "simple net",
			input: Network{
				Nets:  []string{"$HOME_NET"},
				Ports: []string{"$HTTP_PORTS"},
			},
			want: "$HOME_NET $HTTP_PORTS",
		},
		{
			name: "complex net",
			input: Network{
				Nets:  []string{"$HOME_NET", "!$FOO_NET", "192.168.0.0/16"},
				Ports: []string{"$HTTP_PORTS", "!53", "$BAR_NET"},
			},
			want: "[$HOME_NET, !$FOO_NET, 192.168.0.0/16] [$HTTP_PORTS, !53, $BAR_NET]",
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestContentString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Content
		want  string
	}{
		{
			name: "basic",
			input: Content{
				Pattern: []byte("AA"),
			},
			want: `content:"AA";`,
		},
		{
			name: "basic escaped char",
			input: Content{
				Pattern: []byte("AA;"),
			},
			want: `content:"AA|3B|";`,
		},
		{
			name: "negated content",
			input: Content{
				Negate:  true,
				Pattern: []byte("AA"),
			},
			want: `content:!"AA";`,
		},
		{
			name: "content with one option",
			input: Content{
				Pattern: []byte("AA"),
				Options: []*ContentOption{
					&ContentOption{
						Name: "http_uri",
					},
				},
			},
			want: `content:"AA"; http_uri;`,
		},
		{
			name: "content with multiple options",
			input: Content{
				Pattern: []byte("AA"),
				Options: []*ContentOption{
					&ContentOption{
						Name: "http_uri",
					},
					&ContentOption{
						Name:  "depth",
						Value: 0,
					},
				},
			},
			want: `content:"AA"; http_uri; depth:0;`,
		},
		{
			name: "content with multiple options and fast_pattern",
			input: Content{
				Pattern: []byte("AA"),
				Options: []*ContentOption{
					&ContentOption{
						Name: "http_uri",
					},
					&ContentOption{
						Name:  "depth",
						Value: 0,
					},
				},
				FastPattern: FastPattern{
					Enabled: true,
				},
			},
			want: `content:"AA"; http_uri; depth:0; fast_pattern;`,
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestContentsString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Contents
		want  string
	}{
		{
			name: "single simple content",
			input: Contents{
				&Content{
					Pattern: []byte("AA"),
				},
			},
			want: `content:"AA";`,
		},
		{
			name: "multiple simple contents",
			input: Contents{
				&Content{
					Pattern: []byte("AA"),
				},
				&Content{
					Pattern: []byte("BB"),
				},
				&Content{
					Pattern: []byte("CC"),
				},
			},
			want: `content:"AA"; content:"BB"; content:"CC";`,
		},
		{
			name: "single sticky buffer",
			input: Contents{
				&Content{
					DataPosition: base64Data,
					Pattern:      []byte("AA"),
				},
			},
			want: `base64_data; content:"AA";`,
		},
		{
			name: "changing sticky buffer",
			input: Contents{
				&Content{
					DataPosition: base64Data,
					Pattern:      []byte("AA"),
				},
				&Content{
					DataPosition: pktData,
					Pattern:      []byte("BB"),
				},
				&Content{
					DataPosition: httpAccept,
					Pattern:      []byte("CC"),
				},
			},
			want: `base64_data; content:"AA"; pkt_data; content:"BB"; http_accept; content:"CC";`,
		},
		{
			name: "changing sticky buffer and complex content",
			input: Contents{
				&Content{
					DataPosition: base64Data,
					Pattern:      []byte("AA"),
					FastPattern: FastPattern{
						Enabled: true,
					},
					Options: []*ContentOption{
						&ContentOption{
							Name:  "offset",
							Value: 10,
						},
						&ContentOption{
							Name:  "depth",
							Value: 50,
						},
					},
				},
				&Content{
					DataPosition: pktData,
					Pattern:      []byte("BB"),
				},
				&Content{
					DataPosition: httpAccept,
					Pattern:      []byte("CC"),
				},
			},
			want: `base64_data; content:"AA"; offset:10; depth:50; fast_pattern; pkt_data; content:"BB"; http_accept; content:"CC";`,
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestPCREString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input PCRE
		want  string
	}{
		{
			name: "basic",
			input: PCRE{
				Pattern: []byte("foo.*bar"),
				Options: []byte("iU"),
			},
			want: `pcre:"/foo.*bar/iU";`,
		},
		{
			name: "negate",
			input: PCRE{
				Negate:  true,
				Pattern: []byte("foo.*bar"),
				Options: []byte("iU"),
			},
			want: `pcre:!"/foo.*bar/iU";`,
		},
		{
			name: "no options",
			input: PCRE{
				Pattern: []byte("foo.*bar"),
			},
			want: `pcre:"/foo.*bar/";`,
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestRuleString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Rule
		want  string
	}{
		{
			name: "rule",
			input: Rule{
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
			want: `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; content:"AA"; sid:1337; rev:2;)`,
		},
		{
			name: "rule with pcre",
			input: Rule{
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
					},
				},
				PCREs: []*PCRE{
					&PCRE{
						Pattern: []byte("foo.*bar"),
						Options: []byte("Ui"),
					},
				},
			},
			want: `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; content:"AA"; pcre:"/foo.*bar/Ui"; sid:1337; rev:2;)`,
		},
		{
			name: "rule with pcre",
			input: Rule{
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
					},
				},
				Tags: map[string]string{
					"classtype": "trojan-activity",
				},
			},
			want: `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; content:"AA"; classtype:trojan-activity; sid:1337; rev:2;)`,
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestParseRule(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rule    string
		want    *Rule
		wantErr bool
	}{
		{
			name:    "non-rule comment",
			rule:    `# Foo header, this describes a file.`,
			wantErr: true,
		},
		{
			name: "simple content",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
		},
		{
			name: "commented rule content",
			rule: `#alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
		},
		{
			name: "bidirectional",
			rule: `alert udp $HOME_NET any <> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; rev:2);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
		},
		{
			name: "not content",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:!"AA");`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"), Negate: true},
				},
			},
		},
		{
			name: "multiple contents",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"AA"; content:"BB");`,
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
				Contents: Contents{
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
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"A|42 43|D|45|");`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte{'A', 0x42, 0x43, 'D', 0x45},
					},
				},
			},
		},
		{
			name: "tags",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:!"AA"; classtype:foo);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"), Negate: true},
				},
				Tags: map[string]string{"classtype": "foo"},
			},
		},
		{
			name: "references",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"A"; reference:cve,2014; reference:url,www.suricata-ids.org);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("A"),
					},
				},
				References: []*Reference{
					&Reference{Type: "cve", Value: "2014"},
					&Reference{Type: "url", Value: "www.suricata-ids.org"},
				},
			},
		},
		{
			name: "content options",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:!"AA"; http_header; offset:3);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
						Negate:  true,
						Options: []*ContentOption{
							&ContentOption{"http_header", 0},
							&ContentOption{"offset", 3},
						},
					},
				},
			},
		},
		{
			name: "multiple contents and options",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; content:"A"; http_header; fast_pattern; content:"B"; http_uri);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", 0},
						},
						FastPattern: FastPattern{Enabled: true},
					},
					&Content{
						Pattern: []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", 0},
						},
					},
				},
			},
		},
		{
			name: "multiple contents and multiple options",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; content:"A"; http_header; fast_pattern:0,42; nocase; content:"B"; http_uri);`,
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
				Contents: Contents{
					&Content{
						Pattern: []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", 0},
							&ContentOption{"nocase", 0},
						},
						FastPattern: FastPattern{Enabled: true, Offset: 0, Length: 42},
					},
					&Content{
						Pattern: []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", 0},
						},
					},
				},
			},
		},
		{
			name: "multiple contents with file_data",
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; msg:"a"; file_data; content:"A"; http_header; nocase; content:"B"; http_uri);`,
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
				Contents: Contents{
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", 0},
							&ContentOption{"nocase", 0},
						},
					},
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", 0},
						},
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
				Contents: Contents{
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", 0},
							&ContentOption{"nocase", 0},
						},
					},
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", 0},
						},
					},
					&Content{
						DataPosition: pktData,
						Pattern:      []byte("C"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", 0},
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
				Contents: Contents{
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
							&ContentOption{"http_uri", 0},
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
				References:  []*Reference{&Reference{Type: "url", Value: "labs.snort.org/docs/17904.html"}},
				Contents: Contents{
					&Content{
						Pattern: []byte("/tongji.js"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", 0},
						},
						FastPattern: FastPattern{Enabled: true, Only: true},
					},
					&Content{
						Pattern: append([]byte("Host"), 0x3a, 0x20),
						Options: []*ContentOption{
							&ContentOption{"http_header", 0},
						},
					},
				},
				PCREs: []*PCRE{
					&PCRE{
						Pattern: []byte(`Host\x3a[^\r\n]*?\.tongji`),
						Options: []byte("Hi"),
					},
				},
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
					&Reference{
						Type:  "url",
						Value: "www.google.com"},
				},
				Contents: Contents{
					&Content{
						Pattern: []byte("blah"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", 0},
						},
					},
				},
				PCREs: []*PCRE{
					&PCRE{
						Pattern: []byte("foo.*bar"),
						Options: []byte("Ui"),
					},
				},
				Tags: map[string]string{
					"flow":      "to_server,established",
					"classtype": "trojan-activity",
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
					&Reference{
						Type:  "url",
						Value: "doc.emergingthreats.net/2009256"},
				},
				Contents: Contents{
					&Content{
						Pattern: []byte{0x31, 0xc9, 0xb1, 0xfc, 0x80, 0x73, 0x0c},
					},
					&Content{
						Pattern: []byte{0x43, 0xe2, 0x8b, 0x9f},
						Options: []*ContentOption{
							&ContentOption{"distance", 0},
						},
					},
				},
				Tags: map[string]string{"flow": "established", "classtype": "shellcode-detect"},
				Metas: Metadatas{
					&Metadata{Key: "created_at", Value: "2010_07_30"},
					&Metadata{Key: "updated_at", Value: "2010_07_30"},
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
				Contents: Contents{
					&Content{
						Pattern:      []byte("<title>Sign in</title>"),
						DataPosition: fileData,
					},
					&Content{
						Pattern:      []byte("name=chalbhai"),
						DataPosition: fileData,
						Options: []*ContentOption{
							&ContentOption{"nocase", 0},
							&ContentOption{"distance", 0},
						},
						FastPattern: FastPattern{Enabled: true},
					},
					&Content{
						Pattern:      []byte{0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3d, 0x22, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22},
						DataPosition: fileData,
						Options: []*ContentOption{
							&ContentOption{"nocase", 0},
							&ContentOption{"distance", 0},
						},
					},
					&Content{
						Pattern:      []byte{0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3d, 0x22, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22},
						DataPosition: fileData,
						Options: []*ContentOption{
							&ContentOption{"nocase", 0},
							&ContentOption{"distance", 0},
						},
					},
				},
				Tags: map[string]string{"flow": "established,from_server", "classtype": "trojan-activity"},
				Metas: Metadatas{
					&Metadata{Key: "former_category", Value: "CURRENT_EVENTS"},
					&Metadata{Key: "created_at", Value: "2015_10_22"},
					&Metadata{Key: "updated_at", Value: "2018_07_12"},
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
				PCREs: []*PCRE{
					&PCRE{
						Pattern: []byte("foo.*bar"),
						Negate:  true,
						Options: []byte("Ui"),
					},
				},
			},
		},
		// Errors
		{
			name:    "invalid direction",
			rule:    `alert udp $HOME_NET any *# $EXTERNAL_NET any (sid:2; msg:"foo"; content:"A");`,
			wantErr: true,
		},
		{
			name:    "invalid sid",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:"a");`,
			wantErr: true,
		},
		{
			name:    "invalid content option",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; content:"foo"; offset:"a");`,
			wantErr: true,
		},
		{
			name:    "invalid content value",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1; content:!; offset:"a");`,
			wantErr: true,
		},
		{
			name:    "invalid msg",
			rule:    `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:2; msg; content:"A");`,
			wantErr: true,
		},
	} {
		got, err := ParseRule(tt.rule)
		if !reflect.DeepEqual(got, tt.want) || (err != nil) != tt.wantErr {
			t.Fatal(spew.Sprintf("%s: got=%+v,%+v; want=%+v,%+v", tt.name, got, err, tt.want, tt.wantErr))
		}
	}
}

func TestRE(t *testing.T) {
	for _, tt := range []struct {
		rule string
		want string
	}{
		{
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"|28|foo"; content:".AA"; within:40);`,
			want: `.*\(foo.{0,40}\.AA`,
		},
	} {
		r, err := ParseRule(tt.rule)
		if err != nil {
			t.Fatalf("re: parse rule failed: %v", err)
		}
		if got := r.RE(); got != tt.want {
			t.Fatalf("re: got=%v; want=%v", got, tt.want)
		}
	}
}

func TestDataPosString(t *testing.T) {
	for _, tt := range []struct {
		val  dataPos
		want string
	}{
		{
			val:  pktData,
			want: "pkt_data",
		},
		{
			val:  base64Data,
			want: "base64_data",
		},
		{
			val:  httpRequestLine,
			want: "http_request_line",
		},
	} {
		s := tt.val.String()
		if s != tt.want {
			t.Fatalf("String: got=%v; want=%v", s, tt.want)
		}
	}
}

func TestIsStickyBuffer(t *testing.T) {
	for _, tt := range []struct {
		buf  string
		want bool
	}{
		{
			buf:  "pkt_data",
			want: true,
		},
		{
			buf:  "foobarbaz",
			want: false,
		},
		{
			buf:  "http_request_line",
			want: true,
		},
	} {
		got := isStickyBuffer(tt.buf)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v", got, tt.want)
		}
	}
}

func TestStickyBuffer(t *testing.T) {
	for _, tt := range []struct {
		s       string
		want    dataPos
		wantErr bool
	}{
		{
			s:       "pkt_data",
			want:    pktData,
			wantErr: false,
		},
		{
			s:       "foobarbaz",
			want:    pktData,
			wantErr: true,
		},
		{
			s:       "http_request_line",
			want:    httpRequestLine,
			wantErr: false,
		},
	} {
		got, gotErr := stickyBuffer(tt.s)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v", got, tt.want)
		}
		if tt.wantErr != (gotErr != nil) {
			t.Fatalf("gotErr=%v; wantErr=%v", gotErr != nil, tt.wantErr)
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
			input: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"|28|foo"; content:".AA"; within:40);`,
		},
		{
			name:  "complex rule",
			input: `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"FOO BAR BLAH"; flow:established,from_server; content:"200"; http_stat_code; file_data; content:"|3d 21 2d 2f|eyJjWEEEEEE"; fast_pattern; content:"|3z 21 2f 2d|"; pcre:"/^(?:[A-Z0-9+/]{1})*(?:[A-Z0-9+/]{1}==|[A-Z0-9+/]{7}=|[A-Z0-9+/]{9})/R"; metadata: former_category BOO; reference:url,this.is.sparta.com/fooblog; classtype:trojan-activity; sid:1111111; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag FOOO, signature_severity Major, created_at 2018_06_25, performance_impact Low, updated_at 2018_09_23;)`,
		},
	} {
		first, _ := ParseRule(tt.input)
		s := first.String()
		second, err := ParseRule(s)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("first=%v; second=%v\ns=%v", first, second, s)
		}
	}
}
