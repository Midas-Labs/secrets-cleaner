package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
)

const maxExecutionOutput = 1 << 20

type CLIExecutor struct {
	Binary string
}

type ExecutionResult struct {
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

func (e CLIExecutor) Execute(ctx context.Context, payload []byte) ([]byte, error) {
	command, err := ParseLocalCommand(payload)
	if err != nil {
		return nil, err
	}
	if e.Binary == "" {
		return nil, errors.New("secretsweep binary path is required")
	}
	args := []string{"--headless", "--action", command.Operation}
	args = append(args, command.Targets...)
	process := exec.CommandContext(ctx, e.Binary, args...)
	output := &cappedBuffer{remaining: maxExecutionOutput}
	process.Stdout = output
	process.Stderr = output
	err = process.Run()
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return nil, fmt.Errorf("start secretsweep: %w", err)
		}
		exitCode = exitError.ExitCode()
	}
	return json.Marshal(ExecutionResult{ExitCode: exitCode, Output: output.String()})
}

type cappedBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	if len(data) > b.remaining {
		data = data[:max(0, b.remaining)]
	}
	if len(data) > 0 {
		_, _ = b.buffer.Write(data)
		b.remaining -= len(data)
	}
	return original, nil
}

func (b *cappedBuffer) String() string { return b.buffer.String() }
