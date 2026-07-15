package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/ebfe/scard"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/globalplatform"
	keycardio "github.com/status-im/keycard-go/io"
	"github.com/urfave/cli/v3"

	"github.com/status-im/keycard-cli/internal"
)

// ShellCommand returns the shell (scripting) command.
func ShellCommand() *cli.Command {
	return &cli.Command{
		Name:  "shell",
		Usage: "Start interactive shell or run a script file",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "Path to script file (reads from stdin if omitted)",
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "Output each command result as a JSON line (JSONL)",
			},
		},
		Action: cmdShell,
	}
}

func cmdShell(ctx context.Context, cmd *cli.Command) error {
	card, cleanup, err := internal.ConnectToCard(cmd.String("reader"))
	if err != nil {
		return err
	}
	defer cleanup()

	scriptFile := cmd.String("file")
	if scriptFile != "" {
		f, err := os.Open(scriptFile)
		if err != nil {
			return fmt.Errorf("error opening script file: %w", err)
		}
		defer f.Close()
		return runShell(card, f, cmd.Bool("json"))
	}

	fi, _ := os.Stdin.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return runShell(card, os.Stdin, cmd.Bool("json"))
	}

	return errors.New("non-interactive shell. You must pipe commands or use -f flag")
}

func runShell(card *scard.Card, input io.Reader, jsonOutput bool) error {
	ch := keycardio.NewNormalChannel(card)
	kc := keycard.NewCommandSet(ch)
	cashKC := keycard.NewCashCommandSet(ch)
	identKC := keycard.NewIdentCommandSet(ch)
	gp := globalplatform.NewCommandSet(ch)

	out := new(bytes.Buffer)
	write := func(s string) { out.WriteString(s) }

	shell := &shellRunner{
		ctx: &shellCtx{
			ch:      ch,
			kc:      kc,
			cashKC:  cashKC,
			identKC: identKC,
			gp:      gp,
			write:   write,
		},
		out:        out,
		jsonOutput: jsonOutput,
	}

	// Build command map from registry
	shell.commands = make(map[string]shellFn, len(RegisterShellCommands()))
	for _, sc := range RegisterShellCommands() {
		shell.commands[sc.name] = sc.handler
	}

	reader := bufio.NewReader(input)
	defer shell.flushOut()

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			break
		}

		err := shell.evalLine(line)
		if err != nil {
			return err
		}

		if readErr == io.EOF {
			break
		}
	}

	return nil
}

type shellRunner struct {
	ctx        *shellCtx
	commands   map[string]shellFn
	out        *bytes.Buffer
	jsonOutput bool
}

func (s *shellRunner) flushOut() {
	if !s.jsonOutput {
		io.Copy(os.Stdout, s.out)
	}
}

func (s *shellRunner) evalLine(rawLine string) error {
	line := strings.TrimSpace(rawLine)
	if len(line) == 0 || strings.HasPrefix(line, "#") {
		return nil
	}

	line, err := s.evalTemplate(line)
	if err != nil {
		return err
	}

	reg := regexp.MustCompile("\\s+")
	parts := reg.Split(line, -1)

	// Handle echo specially (built-in, not in registry)
	if parts[0] == "echo" {
		msg := strings.Join(parts[1:], " ")
		if s.jsonOutput {
			line := map[string]interface{}{
				"command": "echo",
				"output":  msg,
			}
			data, _ := json.Marshal(line)
			fmt.Fprintln(os.Stdout, string(data))
		} else {
			s.ctx.write(fmt.Sprintf("> %s\n", msg))
		}
		return nil
	}

	if cmd, ok := s.commands[parts[0]]; ok {
		output, err := cmd(s.ctx, parts[1:])
		if err != nil {
			if s.jsonOutput {
				line := map[string]interface{}{
					"command": parts[0],
					"error":   err.Error(),
				}
				data, _ := json.Marshal(line)
				fmt.Fprintln(os.Stderr, string(data))
			}
			return err
		}
		if output != nil {
			if s.jsonOutput {
				line := map[string]interface{}{
					"command": parts[0],
					"result":  output.Result,
				}
				data, _ := json.Marshal(line)
				fmt.Fprintln(os.Stdout, string(data))
			} else {
				s.ctx.write(output.Text)
			}
		}
		return nil
	}

	return fmt.Errorf("command not found: %s", parts[0])
}

func (s *shellRunner) evalTemplate(text string) (string, error) {
	funcMap := template.FuncMap{
		"env": func(name string) (string, error) {
			value := os.Getenv(name)
			if value == "" {
				return "", fmt.Errorf("env variable is empty: %s", name)
			}
			return value, nil
		},
		"session_pairing_key": func() (string, error) {
			pairing := s.ctx.kc.Pairing()
			if pairing == nil {
				return "", errors.New("pairing key not known")
			}
			key := pairing.Key()
			return fmt.Sprintf("%x", key[:]), nil
		},
		"session_pairing_index": func() (string, error) {
			pairing := s.ctx.kc.Pairing()
			if pairing == nil {
				return "", errors.New("pairing index not known")
			}
			return fmt.Sprintf("%d", pairing.Index()), nil
		},
		"session_pin": func() (string, error) {
			if s.ctx.secrets == nil {
				return "", errors.New("pin is not set")
			}
			return s.ctx.secrets.Pin(), nil
		},
		"session_puk": func() (string, error) {
			if s.ctx.secrets == nil {
				return "", errors.New("puk is not set")
			}
			return s.ctx.secrets.Puk(), nil
		},
		"session_pairing_password": func() (string, error) {
			if s.ctx.secrets == nil {
				return "", errors.New("pairing password is not set")
			}
			return s.ctx.secrets.PairingPass(), nil
		},
	}

	tpl, err := template.New("").Funcs(funcMap).Parse(text)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBufferString("")
	err = tpl.Execute(buf, nil)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
