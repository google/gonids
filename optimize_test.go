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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
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
				Contents: Contents{
					&Content{
						Pattern: []byte("AA"),
						Options: []*ContentOption{
							&ContentOption{"http_header", ""},
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
				Contents: Contents{
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
				Contents: Contents{
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
		if tt.wantMod && !reflect.DeepEqual(tt.output, tt.input) {
			t.Fatalf("got:\n%v\nwant:\n%v", tt.input, tt.output)
		}
	}
}
