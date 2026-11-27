package main

import (
	"fmt"
	"regexp"
	"strings"
)

type printer struct{ color bool }

var controlChars = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)

func clean(input string) string {
	input = controlChars.ReplaceAllString(input, " ")
	input = strings.Join(strings.Fields(input), " ")
	if len(input) > 240 {
		input = input[:240] + "..."
	}
	return input
}
func (p printer) wrap(code, message string) string {
	if p.color {
		return "\x1b[" + code + "m" + message + "\x1b[0m"
	}
	return message
}
func (p printer) header(format string, args ...any) {
	fmt.Println("\n" + p.wrap("1;36", "[*] "+fmt.Sprintf(format, args...)))
}
func (p printer) note(format string, args ...any) {
	fmt.Println(p.wrap("36", "[*] "+fmt.Sprintf(format, args...)))
}
func (p printer) open(port int, name string) {
	fmt.Printf("%s %5d/tcp  OPEN  %s\n", p.wrap("1;32", "[+]"), port, name)
}
func (p printer) finding(port int, field, value string) {
	fmt.Printf("    %s %-18s %s\n", p.wrap("33", "├─"), field+":", clean(value))
}
func (p printer) warn(port int, message string) {
	fmt.Printf("    %s %s\n", p.wrap("33", "[!]"), clean(message))
}
