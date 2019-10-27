gonids is a library to parse IDS rules for engines like Snort and Suricata.

### Installation
```
$ go get github.com/google/gonids
```

### Quick Start
Add this import line to the file you're working in:
```
import "github.com/google/gonids"
```

To parse a rule:
```
rule := `alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"GONIDS TEST hello world"; flow:established,to_server; content:"hello world"; classtype:trojan-activity; sid:1; rev:1;)`
r, err := gonids.ParseRule(rule)
if err != nil {
  // Handle parse error
}
// Do something with your rule.
switch r.Action {
case "alert":
  // This is an 'alert' rule.
case "drop":
  // This is a 'drop' rule.
case "pass":
  // This is a 'pass' rule.
default:
  // I have no idea what this would be. =)
}
```

To create a rule a DNS rule (using dns_query sticky buffer) and print it:
```
r := gonids.Rule{
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
}

badDomain := "c2.evil.com"
dnsRule.Description = fmt.Sprintf("DNS query for %s", badDomain)

sb, _ := gonids.StickyBuffer("dns_query")
c := &gonids.Content{
			DataPosition: sb,
			Pattern:      []byte(badDomain),
			Options: []*gonids.ContentOption{
				{"nocase", ""},
			},
		}
}

fmt.Println(r)
```

To optimize a Snort HTTP rule for Suricata:
```
rule := `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"GONIDS TEST hello world"; flow:established,to_server; content:"hello.php"; http_uri; classtype:trojan-activity; sid:1; rev:1;)`
r, err := gonids.ParseRule(rule)
if err != nil {
  // Handle parse error
}
r.OptimizeHTTP()
```

### Miscellaneous
This is not an official Google product.
