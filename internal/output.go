package internal

import (
	"encoding/json"
	"fmt"
	"os"
)

// OutputMode controls output format.
type OutputMode int

const (
	OutputHuman OutputMode = iota
	OutputJSON
)

// PrintJSON marshals v to JSON and writes to stdout.
func PrintJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(data))
	return nil
}

// PrintErrorJSON writes an error as JSON to stderr.
func PrintErrorJSON(message string, sw string) {
	type errOut struct {
		Error string `json:"error"`
		SW    string `json:"sw,omitempty"`
	}
	v := errOut{Error: message}
	if sw != "" {
		v.SW = sw
	}
	data, _ := json.Marshal(v)
	fmt.Fprintln(os.Stderr, string(data))
}
