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
	"errors"
	"reflect"
	"testing"
)

// collect gathers the emitted items into a slice.
func collect(input string) (items []item, err error) {
	l, err := lex(input)
	if err != nil {
		return nil, err
	}
	for item := l.nextItem(); item.typ != itemEOF; item = l.nextItem() {
		switch item.typ {
		case itemError:
			return nil, errors.New(item.value)
		default:
			items = append(items, item)
		}
	}
	return
}

func TestLexer(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		wantErr bool
		items   []item
	}{
		{
			name:  "simple",
			input: "alert udp $HOME_NET any -> [1.1.1.1,2.2.2.2] any (key1:value1; key2:value2;)",
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "udp"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "[1.1.1.1,2.2.2.2]"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "key1"},
				{itemOptionValue, "value1"},
				{itemOptionKey, "key2"},
				{itemOptionValue, "value2"},
				{itemEOR, ""},
			},
		},
		{
			name:  "string value",
			input: `alert tcp-pkt $HOME_NET any -> [1.1.1.1,2.2.2.2] any (key1:"value1";)`,
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "tcp-pkt"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "[1.1.1.1,2.2.2.2]"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "key1"},
				{itemOptionValueString, "value1"},
				{itemEOR, ""},
			},
		},
		{
			name:  "string value not",
			input: `alert udp $HOME_NET any -> [1.1.1.1,2.2.2.2] any (key1:!"value1";)`,
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "udp"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "[1.1.1.1,2.2.2.2]"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "key1"},
				{itemNot, "!"},
				{itemOptionValueString, "value1"},
				{itemEOR, ""},
			},
		},
		{
			name:  "protocol with number",
			input: `alert ipv6 $HOME_NET any -> $EXTERNAL_NET any (key1:"value1";)`,
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "ipv6"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "$EXTERNAL_NET"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "key1"},
				{itemOptionValueString, "value1"},
				{itemEOR, ""},
			},
		},
		{
			name:  "single key",
			input: "alert udp $HOME_NET any -> [1.1.1.1,2.2.2.2] any (key;)",
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "udp"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "[1.1.1.1,2.2.2.2]"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "key"},
				{itemOptionNoValue, ""},
				{itemEOR, ""},
			},
		},
		{
			name:  "multiple spaces",
			input: "\talert   udp   $HOME_NET   any   ->   [1.1.1.1,2.2.2.2]   any   (key1: value1 ; key2;)",
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "udp"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "[1.1.1.1,2.2.2.2]"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "key1"},
				{itemOptionValue, "value1"},
				{itemOptionKey, "key2"},
				{itemOptionNoValue, ""},
				{itemEOR, ""},
			},
		},
		{
			name:  "parentheses in value",
			input: `alert dns $HOME_NET any -> any any (reference:url,en.wikipedia.org/wiki/Tor_(anonymity_network); sid:42;)`,
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "dns"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "any"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "reference"},
				{itemOptionValue, "url,en.wikipedia.org/wiki/Tor_(anonymity_network)"},
				{itemOptionKey, "sid"},
				{itemOptionValue, "42"},
				{itemEOR, ""},
			},
		},
		{
			name:  "escaped quote",
			input: `alert udp $HOME_NET any -> $EXTERNAL_NET any (pcre:"/[=\"]\w{8}\.jar/Hi";)`,
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "udp"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "$EXTERNAL_NET"},
				{itemDestinationPort, "any"},
				{itemOptionKey, "pcre"},
				{itemOptionValueString, `/[=\"]\w{8}\.jar/Hi`},
				{itemEOR, ""},
			},
		},
		{
			name:  "escaped backslash",
			input: `alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (content:"CWD C|3a|\\WINDOWS\\system32\\"; sid:42;)`,
			items: []item{
				{itemAction, "alert"},
				{itemProtocol, "tcp"},
				{itemSourceAddress, "$HOME_NET"},
				{itemSourcePort, "any"},
				{itemDirection, "->"},
				{itemDestinationAddress, "$EXTERNAL_NET"},
				{itemDestinationPort, "21"},
				{itemOptionKey, "content"},
				{itemOptionValueString, `CWD C|3a|\\WINDOWS\\system32\\`},
				{itemOptionKey, "sid"},
				{itemOptionValue, "42"},
				{itemEOR, ""},
			},
		},
		{
			name:  "comment",
			input: "# bla",
			items: []item{{itemComment, "bla"}},
		},
		// errors.
		{
			name:    "invalid utf-8",
			input:   "\xab\x00\xfc",
			wantErr: true,
		},
		{
			name:    "invalid action",
			input:   "42 udp $HOME_NET any -> any any (key);",
			wantErr: true,
		},
		{
			name:    "invalid direction",
			input:   "alert udp $HOME_NET any foo any any (key);",
			wantErr: true,
		},
		{
			name:    "source address EOF",
			input:   "alert udp incomplet",
			wantErr: true,
		},
		{
			name:    "source port EOF",
			input:   "alert udp $HOME_NET incomplet",
			wantErr: true,
		},
		{
			name:    "destination address EOF",
			input:   "alert udp $HOME_NET any -> incomplet",
			wantErr: true,
		},
		{
			name:    "destination port EOF",
			input:   "alert udp $HOME_NET any -> $EXTERNAL_NET incomplet",
			wantErr: true,
		},
		{
			name:    "option key EOF",
			input:   "alert udp $HOME_NET any -> $EXTERNAL_NET any (incomplet",
			wantErr: true,
		},
		{
			name:    "value string EOF",
			input:   "alert udp $HOME_NET any -> $EXTERNAL_NET any (key1:\"incomplet",
			wantErr: true,
		},
		{
			name:    "value EOF",
			input:   "alert udp $HOME_NET any -> $EXTERNAL_NET any (key1:incomplet",
			wantErr: true,
		},
	} {
		lexItems, err := collect(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("%s: got err %v; expected err %v", tt.name, err, tt.wantErr)
		}
		if len(lexItems) != len(tt.items) {
			t.Fatalf("%s: got %d items; expected %d items", tt.name, len(lexItems), len(tt.items))
		}
		for i, lexItem := range lexItems {
			if !reflect.DeepEqual(lexItem, tt.items[i]) {
				t.Errorf("%s: got %+v; expected: %+v", tt.name, lexItem, tt.items[i])
			}
		}
	}
}
