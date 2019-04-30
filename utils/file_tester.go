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
