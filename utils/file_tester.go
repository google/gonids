package main

import (
	"bufio"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gonids"
	"log"
	"os"
)

func commentFail(r *gonids.Rule) bool {
	if r.SID == 0 && r.Revision == 0 && r.Description == "" {
		return true
	}
	return false
}

func main() {
	test := "/home/duane/Downloads/rules/emerging-trojan.rules"
	s1 := []byte(`Content-Disposition`)
	var b1 byte = 0x3a
	s2 := []byte(` form-data`)
	var b2 byte = 0x3b
	s3 := []byte(`name=`)
	var b3 byte = 0x22
	s4 := []byte(` file`)
	b4 := []byte{0x22, 0x3b}
	s5 := []byte(`filename=`)
	var b5 byte = 0x22
	s6 := []byte(`C`)
	var b6 byte = 0x3a
	s7 := []byte(`\`)
	bslice := append(s1, b1)
	bslice = append(bslice, s2...)
	bslice = append(bslice, b2)
	bslice = append(bslice, s3...)
	bslice = append(bslice, b3)
	bslice = append(bslice, s4...)
	bslice = append(bslice, b4...)
	bslice = append(bslice, s5...)
	bslice = append(bslice, b5)
	bslice = append(bslice, s6...)
	bslice = append(bslice, b6)
	bslice = append(bslice, s7...)

	fmt.Println(fmt.Sprintf("% 02x ", bslice))
	return
	fmt.Println(fmt.Sprintf("reading from: %s", test))
	file, err := os.Open(test)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	good := 0
	bad := 0
	for scanner.Scan() {
		t := scanner.Text()
		r1, err := gonids.ParseRule(t)
		if err != nil {
			fmt.Println(fmt.Sprintf("error parsing: %v", err))
			continue
		}
		if commentFail(r1) {
			// fmt.Println(fmt.Sprintf("%v", t))
			continue
		}

		r2, err := gonids.ParseRule(r1.String())
		if err != nil {
			fmt.Println(fmt.Sprintf("fail to parse rule2.\n%s", t))
			bad++
			continue
		}

		if !cmp.Equal(r1, r2) {
			fmt.Println(fmt.Sprintf("failed on:\n%s", r1))
			bad++
			continue
		}
		good++
	}
	fmt.Println(fmt.Sprintf("good:%d\nbad: %d", good, bad))

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}
