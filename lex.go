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
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// item represents a token or text string returned from the lexer.
type item struct {
	typ   itemType // The type of this item.
	value string   // The value of this item.
}

// String returns a string describing an item.
func (i item) String() string {
	switch i.typ {
	case itemEOF:
		return "EOF"
	case itemError:
		return i.value
	}
	return fmt.Sprintf("%q: %s", i.typ, i.value)
}

type itemType int

const (
	itemError itemType = iota
	itemComment
	itemAction
	itemProtocol
	itemSourceAddress
	itemSourcePort
	itemDirection
	itemDestinationAddress
	itemDestinationPort
	itemNot
	itemOptionKey
	itemOptionValue
	itemOptionNoValue
	itemOptionValueString
	itemEOR
	itemEOF
)

const eof = -1

// stateFn represents the state of the scanner as a function that returns the next state.
type stateFn func(*lexer) stateFn

// lexer holds the state of the scanner.
type lexer struct {
	input string    // the string being scanned
	state stateFn   // the next lexing function to enter
	pos   int       // current position in the input
	start int       // start position of this item
	width int       // width of last rune read from input
	items chan item // channel of scanned items
}

// next returns the next rune in the input.
func (l *lexer) next() rune {
	if l.pos >= len(l.input) {
		l.width = 0
		return eof
	}
	r, w := utf8.DecodeRuneInString(l.input[l.pos:])
	if r == utf8.RuneError && w == 1 {
		// The whole input string has been validated at init.
		panic("invalid UTF-8 character")
	}
	l.width = w
	l.pos += l.width
	return r
}

// skipNext skips over the next rune in the input.
func (l *lexer) skipNext() {
	l.next()
	l.ignore()
}

// peek returns but does not consume the next rune in the input.
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

// len returns the current length of the item in processing.
func (l *lexer) len() int {
	if l.pos >= len(l.input) {
		return -1
	}
	return l.pos - l.start
}

// backup steps back one rune. Can only be called once per call of next.
func (l *lexer) backup() {
	if l.width == -1 {
		panic("double backup")
	}
	l.pos -= l.width
	l.width = -1
}

// emit passes an item back to the client, trimSpaces can be used to trim spaces around item
// value before emiting.
func (l *lexer) emit(t itemType, trimSpaces bool) {
	input := l.input[l.start:l.pos]
	if trimSpaces {
		input = strings.TrimSpace(input)
	}

	// This is a bit of a hack. We lex until `;` now so we end up with extra `"`.
	input = strings.TrimSuffix(input, `"`)
	l.items <- item{t, input}
	l.start = l.pos
}

// ignore skips over the pending input before this point.
func (l *lexer) ignore() {
	l.start = l.pos
}

// accept consumes the next rune if it's from the valid set.
func (l *lexer) accept(valid string) bool {
	if strings.ContainsRune(valid, l.next()) {
		return true
	}
	l.backup()
	return false
}

// acceptRun consumes a run of runes from the valid set.
func (l *lexer) acceptRun(valid string) {
	for strings.ContainsRune(valid, l.next()) {
	}
	l.backup()
}

// ignoreSpaces ignores all spaces at the start of the input.
func (l *lexer) ignoreSpaces() {
	for unicode.IsSpace(l.next()) {
		l.ignore()
	}
	l.backup()
}

// errorf returns an error token and terminates the scan by passing
// back a nil pointer that will be the next state, terminating l.nextItem.
func (l *lexer) errorf(format string, args ...interface{}) stateFn {
	l.items <- item{itemError, fmt.Sprintf(format, args...)}
	return nil
}

func (l *lexer) unexpectedEOF() stateFn {
	return nil
}

// nextItem returns the next item from the input.
func (l *lexer) nextItem() item {
	r, more := <-l.items
	if !more {
		return item{itemError, "unexpected EOF"}
	}
	return r
}

// lex initializes and runs a new scanner for the input string.
func lex(input string) (*lexer, error) {
	if !utf8.ValidString(input) {
		return nil, errors.New("input is not a valid UTF-8 string")
	}
	l := &lexer{
		input: input,
		items: make(chan item, 0x1000),
	}
	go l.run()
	return l, nil
}

// TODO: handle error and corner case in all states.
// run runs the state machine for the lexer.
func (l *lexer) run() {
	for l.state = lexRule; l.state != nil; {
		l.state = l.state(l)
	}
	close(l.items)
}

func (l *lexer) close() {
	// Reads all items until channel close to be sure goroutine has ended.
	more := true
	for more {
		_, more = <-l.items
	}
}

// lexRule starts the scan of a rule.
func lexRule(l *lexer) stateFn {
	r := l.next()
	switch {
	case unicode.IsSpace(r):
		l.ignore()
		return lexRule
	case r == '#':
		return lexComment
	case r == eof:
		l.emit(itemEOF, false)
		return nil
	}
	return lexAction
}

// lexComment consumes a commented rule.
func lexComment(l *lexer) stateFn {
	// Ignore leading spaces and #.
	l.ignore()
	for {
		r := l.next()
		if unicode.IsSpace(r) || r == '#' {
			l.ignore()
		} else {
			break
		}
	}
	l.backup()

	for {
		switch l.next() {
		case '\r', '\n':
			l.emit(itemComment, false)
			return lexRule
		case eof:
			l.backup()
			l.emit(itemComment, false)
			return lexRule
		}
	}
}

// lexAction consumes a rule action.
func lexAction(l *lexer) stateFn {
	for {
		r := l.next()
		switch {
		case r == ' ':
			l.emit(itemAction, true)
			return lexProtocol
		case !unicode.IsLetter(r):
			return l.errorf("invalid character %q for a rule action", r)
		}
	}
}

// lexProtocol consumes a rule protocol.
func lexProtocol(l *lexer) stateFn {
	l.ignoreSpaces()
	for {
		r := l.next()
		switch {
		case r == ' ':
			l.emit(itemProtocol, true)
			return lexSourceAddress
		case !(unicode.IsLetter(r) || unicode.IsDigit(r) || (l.len() > 0 && r == '-')):
			return l.errorf("invalid character %q for a rule protocol", r)
		}
	}

}

// lexSourceAddress consumes a source address.
func lexSourceAddress(l *lexer) stateFn {
	l.ignoreSpaces()
	for {
		switch l.next() {
		case ' ':
			l.emit(itemSourceAddress, true)
			return lexSourcePort
		case eof:
			return l.unexpectedEOF()
		}
	}
}

// lexSourcePort consumes a source port.
func lexSourcePort(l *lexer) stateFn {
	l.ignoreSpaces()
	for {
		switch l.next() {
		case ' ':
			l.emit(itemSourcePort, true)
			return lexDirection
		case eof:
			return l.unexpectedEOF()
		}
	}
}

// lexDirection consumes a rule direction.
func lexDirection(l *lexer) stateFn {
	l.ignoreSpaces()
	l.acceptRun("<->")
	if r := l.next(); r != ' ' {
		return l.errorf("invalid character %q for a rule direction", r)
	}
	l.emit(itemDirection, true)
	return lexDestinationAddress
}

// lexDestinationAddress consumes a destination address.
func lexDestinationAddress(l *lexer) stateFn {
	l.ignoreSpaces()
	for {
		switch l.next() {
		case ' ':
			l.emit(itemDestinationAddress, true)
			return lexDestinationPort
		case eof:
			return l.unexpectedEOF()
		}
	}
}

// lexDestinationPort consumes a destination port.
func lexDestinationPort(l *lexer) stateFn {
	for {
		switch l.next() {
		case '(':
			l.backup()
			l.emit(itemDestinationPort, true)
			l.skipNext()
			return lexOptionKey
		case eof:
			return l.unexpectedEOF()
		}
	}
}

// lexOptionKey scans a key from the rule options.
func lexOptionKey(l *lexer) stateFn {
	for {
		switch l.next() {
		case ':':
			l.backup()
			l.emit(itemOptionKey, true)
			l.skipNext()
			return lexOptionValueBegin
		case ';':
			l.backup()
			if l.pos > l.start {
				l.emit(itemOptionKey, true)
				l.emit(itemOptionNoValue, true)
			}
			l.skipNext()
			return lexOptionKey
		case ')':
			l.backup()
			if l.pos > l.start {
				l.emit(itemOptionKey, true)
			}
			l.skipNext()
			return lexRuleEnd
		case eof:
			return l.unexpectedEOF()
		}
	}
}

// lexOptionValueBegin scans the beginning of a value from the rule option.
func lexOptionValueBegin(l *lexer) stateFn {
	switch l.next() {
	case '"':
		l.ignore()
		return lexOptionValueString
	case ' ':
		l.ignore()
		return lexOptionValueBegin
	case '!':
		l.emit(itemNot, true)
		return lexOptionValueBegin
	}
	return lexOptionValue
}

// lexOptionValueString consumes the inner content of a string value from the rule options.
func lexOptionValueString(l *lexer) stateFn {
	escaped := false
	for {
		switch l.next() {
		case ';':
			l.backup()
			l.emit(itemOptionValueString, false)
			l.skipNext()
			return lexOptionKey
		case '\\':
			escaped = !escaped
			if l.next() != ';' || !escaped {
				l.backup()
			}
		case eof:
			return l.unexpectedEOF()
		default:
			escaped = false
		}
	}
}

// lexOptionValue scans a value from the rule options.
func lexOptionValue(l *lexer) stateFn {
	for {
		switch l.next() {
		case ';':
			l.backup()
			l.emit(itemOptionValue, true)
			l.skipNext()
			return lexOptionKey
		case eof:
			return l.unexpectedEOF()
		}
	}
}

// lexOptionEnd marks the end of a rule.
func lexRuleEnd(l *lexer) stateFn {
	l.emit(itemEOR, false)
	return lexRule
}
