/* Copyright 2026 Google Inc.

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

// rulefmt formats and checks IDS rule files (Snort, Suricata).
//
// Usage:
//
//	rulefmt [flags] [path ...]
//
// The flags are:
//
//	-d, -diff
//		Do not print reformatted sources to stdout.
//		If a file's formatting is different from rulefmt's, print diffs
//		to standard output.
//	-l, -list
//		Do not print reformatted sources to stdout.
//		If a file's formatting is different from rulefmt's, print its name
//		to standard output.
//	-w, -write
//		Do not print reformatted sources to stdout.
//		If a file's formatting is different from rulefmt's, overwrite it
//		with rulefmt's version.
//	-c, -check
//		Check if files are formatted and parseable. If any file is unformatted
//		or has parse errors, exit with status 1.
//	-t, -lint
//		Run rule linting checks (e.g. missing SID, expensive PCRE, should be HTTP).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gonids"
	"github.com/kylelemons/godebug/diff"
)

var (
	list     = flag.Bool("l", false, "list files whose formatting differs from rulefmt's")
	write    = flag.Bool("w", false, "write result to (source) file instead of stdout")
	doDiff   = flag.Bool("d", false, "display diffs instead of rewriting files")
	check    = flag.Bool("c", false, "check formatting; exit non-zero if unformatted or invalid")
	lint     = flag.Bool("t", false, "run rule linting checks")
	exitCode = 0
)

func init() {
	flag.BoolVar(list, "list", false, "list files whose formatting differs from rulefmt's")
	flag.BoolVar(write, "write", false, "write result to (source) file instead of stdout")
	flag.BoolVar(doDiff, "diff", false, "display diffs instead of rewriting files")
	flag.BoolVar(check, "check", false, "check formatting; exit non-zero if unformatted or invalid")
	flag.BoolVar(lint, "lint", false, "run rule linting checks")
}

func report(err error) {
	fmt.Fprintf(os.Stderr, "rulefmt: %v\n", err)
	exitCode = 2
}

func processFile(filename string, in io.Reader, out io.Writer) error {
	var buf bytes.Buffer
	if err := gonids.Format(in, &buf); err != nil {
		if *check && exitCode == 0 {
			exitCode = 1
		}
		return err
	}
	res := buf.Bytes()

	if *lint {
		runLinter(filename, bytes.NewReader(res))
	}

	if filename == "<standard input>" || filename == "-" {
		if _, err := out.Write(res); err != nil {
			return err
		}
		return nil
	}

	src, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	if !bytes.Equal(src, res) {
		if *list {
			if _, err := fmt.Fprintln(out, filename); err != nil {
				return err
			}
		}
		if *write {
			err = os.WriteFile(filename, res, 0644)
			if err != nil {
				return err
			}
		}
		if *doDiff {
			data := diff.Diff(string(src), string(res))
			if _, err := fmt.Fprintf(out, "diff %s rulefmt/%s\n", filename, filename); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, data); err != nil {
				return err
			}
		}
		if *check {
			fmt.Fprintf(os.Stderr, "%s is not formatted\n", filename)
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}

	if !*list && !*write && !*doDiff && !*check {
		_, err = out.Write(res)
		return err
	}

	return nil
}

func runLinter(filename string, r io.Reader) {
	scanner := gonids.NewRuleScanner(r)
	for scanner.Scan() {
		rule := scanner.Rule()
		if rule.SID == 0 {
			fmt.Fprintf(os.Stderr, "%s:%d: warning: rule missing SID\n", filename, scanner.LineNumber())
		}
		if rule.ShouldBeHTTP() {
			fmt.Fprintf(os.Stderr, "%s:%d: warning: rule uses HTTP buffers but protocol is not http (SID: %d)\n", filename, scanner.LineNumber(), rule.SID)
		}
		if rule.ExpensivePCRE() {
			fmt.Fprintf(os.Stderr, "%s:%d: warning: rule may have expensive PCRE (SID: %d)\n", filename, scanner.LineNumber(), rule.SID)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", filename, err)
		if exitCode == 0 {
			exitCode = 1
		}
	}
}

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		if err := processFile("<standard input>", os.Stdin, os.Stdout); err != nil {
			report(err)
		}
		os.Exit(exitCode)
	}

	for _, path := range args {
		if path == "-" {
			if err := processFile("<standard input>", os.Stdin, os.Stdout); err != nil {
				report(err)
			}
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			report(err)
			continue
		}
		if info.IsDir() {
			err = filepath.Walk(path, func(p string, i os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !i.IsDir() && strings.HasSuffix(p, ".rules") {
					f, err := os.Open(p)
					if err != nil {
						report(err)
						return nil
					}
					if err := processFile(p, f, os.Stdout); err != nil {
						report(fmt.Errorf("%s: %w", p, err))
					}
					if err := f.Close(); err != nil {
						report(err)
					}
				}
				return nil
			})
			if err != nil {
				report(err)
			}
		} else {
			f, err := os.Open(path)
			if err != nil {
				report(err)
				continue
			}
			if err := processFile(path, f, os.Stdout); err != nil {
				report(fmt.Errorf("%s: %w", path, err))
			}
			if err := f.Close(); err != nil {
				report(err)
			}
		}
	}

	os.Exit(exitCode)
}
