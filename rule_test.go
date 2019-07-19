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
)

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
		{
			name: "double backslash",
			input: &Content{
				Pattern: []byte(`C|3a|\\WINDOWS\\system32\\`),
			},
			want: `C|3a|\\WINDOWS\\system32\\`,
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
				Value: "0",
			},
			want: "depth:0;",
		},
		{
			name: "invalid value",
			input: ContentOption{
				Name:  "http_uri",
				Value: "1",
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
		{
			name:  "busted",
			input: []string{"82.163.143.135", "82.163.142.137"},
			want:  "[82.163.143.135, 82.163.142.137]",
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
						Value: "0",
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
						Value: "0",
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
							Value: "10",
						},
						&ContentOption{
							Name:  "depth",
							Value: "50",
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

func TestRE(t *testing.T) {
	for _, tt := range []struct {
		rule string
		want string
	}{
		{
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"|28|foo"; content:".AA"; within:40;)`,
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
		got, gotErr := StickyBuffer(tt.s)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v", got, tt.want)
		}
		if tt.wantErr != (gotErr != nil) {
			t.Fatalf("gotErr=%v; wantErr=%v", gotErr != nil, tt.wantErr)
		}

	}
}
