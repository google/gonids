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
				Contents: Contents{
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
				Contents: Contents{
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
				Contents: Contents{
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
				Contents: Contents{
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
				Contents: Contents{
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"), Negate: true},
				},
				Tags: map[string]string{"classtype": "foo"},
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
						Negate:  true,
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
							&ContentOption{"offset", "3"},
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
				Contents: Contents{
					&Content{
						Pattern: []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
						},
						FastPattern: FastPattern{Enabled: true},
					},
					&Content{
						Pattern: []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", ""},
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
				Contents: Contents{
					&Content{
						Pattern: []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
							&ContentOption{"nocase", ""},
						},
						FastPattern: FastPattern{Enabled: true, Offset: 0, Length: 42},
					},
					&Content{
						Pattern: []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", ""},
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
				Contents: Contents{
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
							&ContentOption{"nocase", ""},
						},
					},
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", ""},
						},
					},
				},
			},
		},
		// Some remnant of the previously parsed rule having fileData set at the end is affecting this.
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
				Contents: Contents{
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
				Contents: Contents{
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("A"),
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
							&ContentOption{"nocase", ""},
						},
					},
					&Content{
						DataPosition: fileData,
						Pattern:      []byte("B"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", ""},
						},
					},
					&Content{
						DataPosition: pktData,
						Pattern:      []byte("C"),
						Options: []*ContentOption{
							&ContentOption{"http_uri", ""},
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
							&ContentOption{"http_uri", ""},
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
							&ContentOption{"http_uri", ""},
						},
						FastPattern: FastPattern{Enabled: true, Only: true},
					},
					&Content{
						Pattern: append([]byte("Host"), 0x3a, 0x20),
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
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
							&ContentOption{"http_uri", ""},
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
							&ContentOption{"distance", "0"},
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
							&ContentOption{"nocase", ""},
							&ContentOption{"distance", "0"},
						},
						FastPattern: FastPattern{Enabled: true},
					},
					&Content{
						Pattern:      []byte{0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3d, 0x22, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22},
						DataPosition: fileData,
						Options: []*ContentOption{
							&ContentOption{"nocase", ""},
							&ContentOption{"distance", "0"},
						},
					},
					&Content{
						Pattern:      []byte{0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3d, 0x22, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22},
						DataPosition: fileData,
						Options: []*ContentOption{
							&ContentOption{"nocase", ""},
							&ContentOption{"distance", "0"},
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
				PCREs: []*PCRE{
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
				Contents: Contents{
					&Content{
						Pattern: []byte{0xff, 0xfe},
						Options: []*ContentOption{
							&ContentOption{"byte_extract", "3,0,Certs.len,relative,little"},
						},
					},
					&Content{
						Pattern: []byte{0x55, 0x04, 0x0A, 0x0C, 0x0C},
						Options: []*ContentOption{
							&ContentOption{"distance", "3"},
							&ContentOption{"within", "Certs.len"},
						},
					},
				},
				Vars: map[string]*Var{
					"Certs.len": {3, 0, []string{"relative", "little"}},
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
			name:    "byte_extract without content",
			rule:    `alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"byte_extract"; byte_extract:3,0,Certs.len,relative; sid:42; rev:1;)`,
			wantErr: true,
		},
	} {
		got, err := ParseRule(tt.rule)
		if !reflect.DeepEqual(got, tt.want) || (err != nil) != tt.wantErr {
			t.Fatal(spew.Sprintf("%s: got=%+v,%+v; want=%+v,%+v", tt.name, got, err, tt.want, tt.wantErr))
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
