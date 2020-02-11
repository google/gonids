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
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

func TestOptimizeHTTP(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *Rule
		output  *Rule
		wantMod bool
	}{
		{
			name: "already http",
			input: &Rule{
				Protocol: "http",
			},
			wantMod: false,
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
			output: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("AA"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "http_optimize",
					},
				},
			},
			wantMod: true,
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
			output: &Rule{
				Protocol: "http",
				Source: Network{
					Nets:  []string{"$HOME_NET"},
					Ports: []string{"any"},
				},
				Destination: Network{
					Nets:  []string{"$EXTERNAL_NET"},
					Ports: []string{"any"},
				},
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpProtocol,
						Pattern:      []byte("AA"),
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "http_optimize",
					},
				},
			},
			wantMod: true,
		},
	} {
		gotMod := tt.input.OptimizeHTTP()
		// Expected modification.
		if gotMod != tt.wantMod {
			t.Fatalf("%s: gotMod %v; expected %v", tt.name, gotMod, tt.wantMod)
		}
		// Actual modifications correctness.
		diff := pretty.Compare(tt.output, tt.input)
		if tt.wantMod && diff != "" {
			t.Fatal(fmt.Sprintf("diff (-got +want):\n%s", diff))
		}
	}
}

func TestSnortURILenFix(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *Rule
		output  *Rule
		wantMod bool
	}{
		{
			name: "urilen exact raw",
			input: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:    uriLen,
						Num:     3,
						Options: []string{"raw"},
					},
				},
			},
			wantMod: false,
		},
		{
			name: "urilen exact norm",
			input: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:    uriLen,
						Num:     3,
						Options: []string{"norm"},
					},
				},
			},
			wantMod: false,
		},
		{
			name: "urilen range",
			input: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     uriLen,
						Min:      3,
						Max:      7,
						Operator: "<>",
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     uriLen,
						Min:      2,
						Max:      8,
						Operator: "<>",
						Options:  []string{"raw"},
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "snort_urilen"},
				},
			},
			wantMod: true,
		},
		{
			name: "urilen exact",
			input: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind: uriLen,
						Num:  3,
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:    uriLen,
						Num:     3,
						Options: []string{"raw"},
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "snort_urilen"},
				},
			},
			wantMod: true,
		},
		{
			name: "urilen range norm",
			input: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     uriLen,
						Min:      3,
						Max:      7,
						Operator: "<>",
						Options:  []string{"norm"},
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&LenMatch{
						Kind:     uriLen,
						Min:      2,
						Max:      8,
						Operator: "<>",
						Options:  []string{"norm"},
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "snort_urilen"},
				},
			},
			wantMod: true,
		},
	} {
		gotMod := tt.input.SnortURILenFix()
		// Expected modification.
		if gotMod != tt.wantMod {
			t.Fatalf("%s: gotMod %v; expected %v", tt.name, gotMod, tt.wantMod)
		}
		// Actual modifications correctness.
		diff := pretty.Compare(tt.output, tt.input)
		if tt.wantMod && diff != "" {
			t.Fatal(fmt.Sprintf("diff (-got +want):\n%s", diff))
		}
	}
}

func TestSnortHTTPHeaderFix(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *Rule
		output  *Rule
		wantMod bool
	}{
		{
			name: "basic test",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foobar\r\n\r\n"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foobar\r\n"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&ByteMatch{
						Kind:     isDataAt,
						Negate:   true,
						NumBytes: "1",
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "snort_http_header"},
				},
			},

			wantMod: true,
		},
		{
			name: "insert middle",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&Content{
						Pattern: []byte("bar\r\n\r\n"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&Content{
						Pattern: []byte("baz"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("foo"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&Content{
						Pattern: []byte("bar\r\n"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
					&ByteMatch{
						Kind:     isDataAt,
						Negate:   true,
						NumBytes: "1",
					},
					&Content{
						Pattern: []byte("baz"),
						Options: []*ContentOption{
							{"http_header", ""},
						},
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "snort_http_header"},
				},
			},

			wantMod: true,
		},
	} {
		gotMod := tt.input.SnortHTTPHeaderFix()
		// Expected modification.
		if gotMod != tt.wantMod {
			t.Fatalf("%s: gotMod %v; expected %v", tt.name, gotMod, tt.wantMod)
		}
		// Actual modifications correctness.
		diff := pretty.Compare(tt.output, tt.input)
		if tt.wantMod && diff != "" {
			t.Fatal(fmt.Sprintf("diff (-got +want):\n%s", diff))
		}
	}
}

func TestUpgradeToSuri5(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *Rule
		output  *Rule
		wantMod bool
	}{
		{
			name: "content modifier",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("/foo.php"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
					&Content{
						Pattern: []byte("?bar=baz"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("/foo.php"),
					},
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("?bar=baz"),
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "upgrade_to_suri5"},
				},
			},

			wantMod: true,
		},
		{
			name: "old sticky buffer",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpRequestLine,
						Pattern:      []byte("foo.php"),
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpRequestLine5,
						Pattern:      []byte("foo.php"),
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "upgrade_to_suri5"},
				},
			},

			wantMod: true,
		},
		{
			name: "old sticky buffer",
			input: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						Pattern: []byte("/foo.php"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},

					&Content{
						DataPosition: httpRequestLine,
						Pattern:      []byte("bar"),
					},
					&Content{
						Pattern: []byte("?baz=bop"),
						Options: []*ContentOption{
							{"http_uri", ""},
						},
					},
				},
			},
			output: &Rule{
				Matchers: []orderedMatcher{
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("/foo.php"),
					},

					&Content{
						DataPosition: httpRequestLine5,
						Pattern:      []byte("bar"),
					},
					&Content{
						DataPosition: httpURI,
						Pattern:      []byte("?baz=bop"),
					},
				},
				Metas: Metadatas{
					&Metadata{
						Key:   "gonids",
						Value: "upgrade_to_suri5"},
				},
			},

			wantMod: true,
		},
	} {
		gotMod := tt.input.UpgradeToSuri5()
		// Expected modification.
		if gotMod != tt.wantMod {
			t.Fatalf("%s: gotMod %v; expected %v", tt.name, gotMod, tt.wantMod)
		}
		// Actual modifications correctness.
		diff := pretty.Compare(tt.output, tt.input)
		if tt.wantMod && diff != "" {
			t.Fatal(fmt.Sprintf("diff (-got +want):\n%s", diff))
		}
	}
}
