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
var rule := "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"GONIDS TEST hello world"; flow:established,to_server; content:"hello world"; classtype:trojan-activity; sid:1; rev:1;)"
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

### Miscellaneous
This is not an official Google product.
