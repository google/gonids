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
	"testing"
)

func TestShouldBeHTTP(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Rule
		want  bool
	}{
		{
			name: "already http",
			input: &Rule{
				Protocol: "http",
			},
			want: false,
		},
		{
			name: "content option change",
			input: &Rule{
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "sticky buffer change",
			input: &Rule{
				Protocol: "tcp",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpProtocol,
						Pattern:      []byte("AA"),
					},
				},
			},
			want: true,
		},
	} {
		got := tt.input.ShouldBeHTTP()
		if got != tt.want {
			t.Fatalf("%s: got %v; want %v", tt.name, got, tt.want)
		}
	}
}

func TestExpensivePCRE(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Rule
		want  bool
	}{
		{
			name: "No PCRE",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AAAAAAAAAA"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "No Content",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&PCRE{
						Pattern: []byte("f.*bar"),
					},
				},
			},
			want: true,
		},
		{
			name: "Short Content",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&PCRE{
						Pattern: []byte("f.*bar"),
					},
				},
			},
			want: true,
		},
		{
			name: "Only Common Content",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("POST"),
						Options: []*ContentOption{
							{"http_method", ""},
						},
					},
					&PCRE{
						Pattern: []byte("f.*bar"),
					},
				},
			},
			want: true,
		},
		{
			name: "Long Content",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("ReallyLongThing"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&PCRE{
						Pattern: []byte("f.*bar"),
					},
				},
			},
			want: false,
		},
		{
			name: "Banned complex content",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("\r\nUser-Agent: "),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&PCRE{
						Pattern: []byte("f.*bar"),
					},
				},
			},
			want: true,
		},
		{
			name: "Banned complex content, with long content",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("\r\nUser-Agent: "),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&Content{
						Pattern: []byte("SuperLongUniqueAwesome"),
					},
					&PCRE{
						Pattern: []byte("f.*bar"),
					},
				},
			},
			want: false,
		},
	} {
		got := tt.input.ExpensivePCRE()
		if got != tt.want {
			t.Fatalf("%s: got %v; want %v", tt.name, got, tt.want)
		}
	}
}

func TestSnortHTTPHeader(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Rule
		want  bool
	}{
		{
			name: "has trailing CRLF CRLF",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AAAAAAAAAA\r\n\r\n"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "multiple content trailing CRLF CRLF",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("BBBBBB"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&Content{
						Pattern: []byte("AAAAAAAAAA\r\n\r\n"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "no trailing CRLF",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("BBBBBB"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "one trailing CRLF",
			input: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"$HTTP_PORTS"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("BBBBBB\r\n"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			want: false,
		},
	} {
		got := tt.input.SnortHTTPHeader()
		if got != tt.want {
			t.Fatalf("%s: got %v; want %v", tt.name, got, tt.want)
		}
	}
}

func TestNoReferences(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Rule
		want  bool
	}{
		{
			name: "has a reference",
			input: &Rule{
				References: []*Reference{
					{
						Type:  "md5",
						Value: "68b329da9893e34099c7d8ad5cb9c940",
					},
				},
			},
			want: false,
		},
		{
			name: "has multiple reference",
			input: &Rule{
				References: []*Reference{
					{
						Type:  "md5",
						Value: "68b329da9893e34099c7d8ad5cb9c940",
					},
					{
						Type:  "md5",
						Value: "68b329da9893e34099c7d8ad5cb9c941",
					},
				},
			},
			want: false,
		},
		{
			name: "has no reference",
			input: &Rule{
				References: []*Reference{},
			},
			want: true,
		},
	} {
		got := tt.input.NoReferences()
		if got != tt.want {
			t.Fatalf("%s: got %v; want %v", tt.name, got, tt.want)
		}
	}
}

func TestOnlyShortContents(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input *Rule
		want  bool
	}{
		{
			name: "long enough content",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AAAAAAAAAA\r\n\r\n"),
					},
				},
			},
			want: false,
		},
		{
			name: "one long one short",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AAAAAAAAAA\r\n\r\n"),
					},
					&Content{
						Pattern: []byte("AAAA"),
					},
				},
			},
			want: false,
		},
		{
			name: "short content",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AAAA"),
					},
				},
			},
			want: true,
		},
		{
			name: "short content and non-content",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AAAA"),
					},
					&ByteMatch{},
				},
			},
			want: false,
		},
	} {
		got := tt.input.OnlyShortContents()
		if got != tt.want {
			t.Fatalf("%s: got %v; want %v", tt.name, got, tt.want)
		}
	}
}
