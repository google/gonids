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
				Contents: Contents{
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
				Contents: Contents{
					&Content{
						DataPosition: httpProtocol,
						Pattern:      []byte("AA"),
					},
				},
			},
			want: true,
		},
	} {
		got := tt.input.OptimizeHTTP()
		// Expected modification.
		if got != tt.want {
			t.Fatalf("%s: got %v; want %v", tt.name, got, tt.want)
		}
	}
}
