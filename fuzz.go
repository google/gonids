package gonids

func FuzzParseRule(data []byte) int {
	r, err := ParseRule(string(data))
	if err != nil {
		// Handle parse error
		return 0
	}
	r.OptimizeHTTP()
	return 1
}
