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
				Pattern: []byte(`C:\\WINDOWS\\system32\\`),
			},
			want: `C|3A|\\WINDOWS\\system32\\`,
		},
		{
			name: "content with hex pipe",
			input: &Content{
				Pattern: []byte(`C|B`),
			},
			want: `C|7C|B`,
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
			name: "fast_pattern:`chop` with 0",
			input: FastPattern{
				Enabled: true,
				Offset:  0,
				Length:  5,
			},
			want: "fast_pattern:0,5;",
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
			want:  "[$HOME_NET,!$FOO_NET,192.168.0.0/16]",
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
			want: "[$HOME_NET,!$FOO_NET,192.168.0.0/16] [$HTTP_PORTS,!53,$BAR_NET]",
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestByteMatchString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input ByteMatch
		want  string
	}{
		{
			name: "byte_test basic",
			input: ByteMatch{
				Kind:     bTest,
				NumBytes: "3",
				Operator: ">",
				Value:    "300",
				Offset:   42,
			},
			want: `byte_test:3,>,300,42;`,
		},
		{
			name: "byte_jump basic",
			input: ByteMatch{
				Kind:     bJump,
				NumBytes: "3",
				Offset:   42,
			},
			want: `byte_jump:3,42;`,
		},
		{
			name: "byte_extract basic",
			input: ByteMatch{
				Kind:     bExtract,
				NumBytes: "3",
				Offset:   42,
				Variable: "foobar",
			},
			want: `byte_extract:3,42,foobar;`,
		},
		{
			name: "byte_test options",
			input: ByteMatch{
				Kind:     bTest,
				NumBytes: "3",
				Operator: ">",
				Value:    "300",
				Offset:   42,
				Options:  []string{"string", "dec"},
			},
			want: `byte_test:3,>,300,42,string,dec;`,
		},
		{
			name: "byte_jump options",
			input: ByteMatch{
				Kind:     bJump,
				NumBytes: "3",
				Offset:   42,
				Options:  []string{"relative", "post_offset 2", "bitmask 0x03f0"},
			},
			want: `byte_jump:3,42,relative,post_offset 2,bitmask 0x03f0;`,
		},
		{
			name: "byte_extract options",
			input: ByteMatch{
				Kind:     bExtract,
				NumBytes: "3",
				Offset:   42,
				Variable: "foobar",
				Options:  []string{"relative", "bitmask 0x03ff"},
			},
			want: `byte_extract:3,42,foobar,relative,bitmask 0x03ff;`,
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestBase64DecodeString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input ByteMatch
		want  string
	}{
		{
			name: "base64_decode bare",
			input: ByteMatch{
				Kind: b64Decode,
			},
			want: `base64_decode;`,
		},
		{
			name: "base64_decode some options",
			input: ByteMatch{
				Kind:     b64Decode,
				NumBytes: "1",
				Options:  []string{"relative"},
			},
			want: `base64_decode:bytes 1,relative;`,
		},
		{
			name: "base64_decode all options",
			input: ByteMatch{
				Kind:     b64Decode,
				NumBytes: "1",
				Offset:   2,
				Options:  []string{"relative"},
			},
			want: `base64_decode:bytes 1,offset 2,relative;`,
		},
	} {
		got := tt.input.base64DecodeString()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestTLSTagString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input TLSTag
		want  string
	}{
		{
			name: "simple quoted",
			input: TLSTag{
				Key:   "tls.subject",
				Value: "CN=*.googleusercontent.com",
			},
			want: `tls.subject:"CN=*.googleusercontent.com";`,
		},
		{
			name: "negated quoted",
			input: TLSTag{
				Negate: true,
				Key:    "tls.issuerdn",
				Value:  "CN=Google-Internet-Authority",
			},
			want: `tls.issuerdn:!"CN=Google-Internet-Authority";`,
		},
		{
			name: "simple unquoted",
			input: TLSTag{
				Key:   "tls.version",
				Value: "1.2",
			},
			want: "tls.version:1.2;",
		},
		// TODO(duane): Confirm if negation of this is valid.
		{
			name: "negated unquoted",
			input: TLSTag{
				Negate: true,
				Key:    "tls.version",
				Value:  "1.2",
			},
			want: "tls.version:!1.2;",
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestLenMatchString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *LenMatch
		want  string
	}{
		{
			name: "no operator",
			input: &LenMatch{
				Kind: iCode,
				Num:  3,
			},
			want: `icode:3;`,
		},
		{
			name: "single operator",
			input: &LenMatch{
				Kind:     iCode,
				Operator: ">",
				Num:      3,
			},
			want: `icode:>3;`,
		},
		{
			name: "min and max",
			input: &LenMatch{
				Kind:     iType,
				Operator: "<>",
				Min:      1,
				Max:      2,
			},
			want: `itype:1<>2;`,
		},
		{
			name: "options",
			input: &LenMatch{
				Kind:     uriLen,
				Operator: "<>",
				Min:      1,
				Max:      2,
				Options:  []string{"raw"},
			},
			want: `urilen:1<>2,raw;`,
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
					{
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
					{
						Name: "http_uri",
					},
					{
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
					{
						Name: "http_uri",
					},
					{
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

func TestFlowbitsString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Flowbit
		want  string
	}{
		{
			name: "action only",
			input: &Flowbit{
				Action: "noalert",
				Value:  "",
			},
			want: `flowbits:noalert;`,
		},
		{
			name: "simple flowbits",
			input: &Flowbit{
				Action: "set",
				Value:  "EvilIP",
			},
			want: `flowbits:set,EvilIP;`,
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestXbitsString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Xbit
		want  string
	}{
		{
			name: "basic set",
			input: &Xbit{
				Action: "set",
				Name:   "foo",
				Track:  "ip_src",
			},
			want: `xbits:set,foo,track ip_src;`,
		},
		{
			name: "with expire set",
			input: &Xbit{
				Action: "set",
				Name:   "foo",
				Track:  "ip_src",
				Expire: "5",
			},
			want: `xbits:set,foo,track ip_src,expire 5;`,
		},
	} {
		got := tt.input.String()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}

func TestFlowintsString(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Flowint
		want  string
	}{
		{
			name: "action only",
			input: &Flowint{
				Name:     "foo",
				Modifier: "+",
				Value:    "1",
			},
			want: `flowint:foo,+,1;`,
		},
		{
			name: "isnotset only",
			input: &Flowint{
				Name:     "foo",
				Modifier: "isnotset",
			},
			want: `flowint:foo,isnotset;`,
		},
		{
			name: "extraneous value",
			input: &Flowint{
				Name:     "foo",
				Modifier: "isnotset",
				Value:    "1",
			},
			want: `flowint:foo,isnotset;`,
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
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
			want: `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; content:"AA"; sid:1337; rev:2;)`,
		},
		{
			name: "rule with datapos",
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
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
					&Content{
						Pattern:      []byte("BB"),
						DataPosition: fileData,
					},
				},
			},
			want: `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; content:"AA"; file_data; content:"BB"; sid:1337; rev:2;)`,
		},
		{
			name: "rule with flow and tag",
			input: Rule{
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
				Revision:    2,
				Description: "foo",
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
				},
				Tags: map[string]string{"flow": "to_server", "app-layer-protocol": "tls"},
			},
			want: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; flow:to_server; content:"AA"; app-layer-protocol:tls; sid:1337; rev:2;)`,
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
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
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
				Tags: map[string]string{
					"classtype": "trojan-activity",
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
					},
				},
			},
			want: `alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"foo"; content:"AA"; classtype:trojan-activity; sid:1337; rev:2;)`,
		},
		{
			name: "rule with flowbits",
			input: Rule{
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
				SID:         1223,
				Revision:    3,
				Description: "Flowbits test",
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
			},
			want: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Flowbits test"; flowbits:set,testbits; flowbits:noalert; sid:1223; rev:3;)`,
		},
		{
			name: "rule with flowints",
			input: Rule{
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
				SID:         1223,
				Revision:    3,
				Description: "Flowints test",
				Flowints: []*Flowint{
					{
						Name:     "foo",
						Modifier: ">",
						Value:    "1",
					},
					{
						Name:     "bar",
						Modifier: "+",
						Value:    "1",
					},
				},
			},
			want: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Flowints test"; flowint:foo,>,1; flowint:bar,+,1; sid:1223; rev:3;)`,
		},
		{
			name: "rule with xbits",
			input: Rule{
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
				SID:         1223,
				Revision:    3,
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
			want: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Xbits test"; xbits:set,foo,track ip_src; xbits:set,bar,track ip_src,expire 60; sid:1223; rev:3;)`,
		},
		{
			name: "rule with bsize",
			input: Rule{
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
						DataPosition: httpURI,
						Kind:         bSize,
						Num:          10,
					},
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("foo"),
					},
				},
			},
			want: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"new sticky buffers"; http.method; content:"POST"; http.uri; bsize:10; content:"foo"; sid:1234; rev:2;)`,
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

func TestLastContent(t *testing.T) {
	for _, tt := range []struct {
		rule string
		want *Content
	}{
		{
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"bar";)`,
			want: &Content{Pattern: []byte("bar")},
		},
		{
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo"; content:"bar"; pcre:"/foo.*bar/iU"; content:"foo"; within:40; pcre:"/foo.*bar.*baz/iU";)`,
			want: &Content{
				Pattern: []byte("foo"),
				Options: []*ContentOption{
					{
						Name:  "within",
						Value: "40",
					},
				},
			},
		},
		{
			rule: `alert udp $HOME_NET any -> $EXTERNAL_NET any (sid:1337; msg:"foo";)`,
			want: nil,
		},
	} {
		r, err := ParseRule(tt.rule)
		if err != nil {
			t.Fatalf("re: parse rule failed: %v", err)
		}
		diff := pretty.Compare(r.LastContent(), tt.want)
		if diff != "" {
			t.Fatalf(fmt.Sprintf("diff (-got +want):\n%s", diff))
		}
	}
}

func TestDataPosString(t *testing.T) {
	for _, tt := range []struct {
		val  DataPos
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
		want    DataPos
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

func TestHasVar(t *testing.T) {
	for _, tt := range []struct {
		name string
		r    *Rule
		s    string
		want bool
	}{
		{
			name: "has var",
			r: &Rule{
				Matchers: []orderedMatcher{
					&ByteMatch{
						Variable: "foovar",
					},
				},
			},
			s:    "foovar",
			want: true,
		},
		{
			name: "has var",
			r: &Rule{
				Matchers: []orderedMatcher{
					&ByteMatch{
						Variable: "barvar",
					},
				},
			},
			s:    "foovar",
			want: false,
		},
		{
			name: "no byte matchers",
			r:    &Rule{},
			s:    "foovar",
			want: false,
		},
	} {
		got := tt.r.HasVar(tt.s)
		if got != tt.want {
			t.Fatalf("got=%v; want=%v", got, tt.want)
		}

	}
}

func TestInsertMatcher(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *Rule
		matcher orderedMatcher
		pos     int
		want    *Rule
		wantErr bool
	}{
		{
			name: "basic test",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			matcher: &Content{
				Pattern: []byte("bar"),
			},
			pos: 0,
			want: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("bar"),
					},
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "insert end",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			matcher: &Content{
				Pattern: []byte("bar"),
			},
			pos: 1,
			want: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
					&Content{
						Pattern: []byte("bar"),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "insert middle",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
					&Content{
						Pattern: []byte("bar"),
					},
				},
			},
			matcher: &Content{
				Pattern: []byte("baz"),
			},
			pos: 1,
			want: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
					&Content{
						Pattern: []byte("baz"),
					},
					&Content{
						Pattern: []byte("bar"),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "insert different type",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
					&Content{
						Pattern: []byte("bar"),
					},
				},
			},
			matcher: &ByteMatch{
				Kind:     isDataAt,
				Negate:   true,
				NumBytes: "1",
			},
			pos: 1,
			want: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
					&ByteMatch{
						Kind:     isDataAt,
						Negate:   true,
						NumBytes: "1",
					},
					&Content{
						Pattern: []byte("bar"),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "index too small",

			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			matcher: &Content{
				Pattern: []byte("bar"),
			},
			pos: -1,
			want: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "index too large",

			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			matcher: &Content{
				Pattern: []byte("bar"),
			},
			pos: 4,
			want: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "effectively append",

			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
				},
			},
			matcher: &Content{
				Pattern: []byte("bar"),
			},
			pos: 1,
			want: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
					},
					&Content{
						Pattern: []byte("bar"),
					},
				},
			},
			wantErr: false,
		},
	} {
		gotErr := tt.input.InsertMatcher(tt.matcher, tt.pos)
		if tt.wantErr != (gotErr != nil) {
			t.Fatalf("gotErr=%v; wantErr=%v", gotErr != nil, tt.wantErr)
		}
		diff := pretty.Compare(tt.input, tt.want)
		if diff != "" {
			t.Fatal(fmt.Sprintf("%s: diff (-got +want):\n%s", tt.name, diff))
		}
	}
}

func TestRuleGetSidMsg(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Rule
		want  string
	}{
		{
			name: "rule",
			input: Rule{
				SID:         1337,
				Description: "foo",
			},
			want: `1337 || foo`,
		},
		{
			name: "rule",
			input: Rule{
				SID:         1337,
				Description: "foo",
				References: []*Reference{
					{
						Type:  "url",
						Value: "www.google.com",
					},
				},
			},
			want: `1337 || foo || url,www.google.com`,
		},
		{
			name: "rule",
			input: Rule{
				SID:         1337,
				Description: "foo",
				References: []*Reference{
					{
						Type:  "url",
						Value: "www.google.com",
					},
					{
						Type:  "md5",
						Value: "2aee1c40199c7754da766e61452612cc",
					},
				},
			},
			want: `1337 || foo || url,www.google.com || md5,2aee1c40199c7754da766e61452612cc`,
		},
	} {
		got := tt.input.GetSidMsg()
		if got != tt.want {
			t.Fatalf("%s: got %v -- expected %v", tt.name, got, tt.want)
		}
	}
}
