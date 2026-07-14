package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// EngineAction is a mode of the clean-secret-from-repos.sh engine.
type EngineAction string

const (
	ActionScan    EngineAction = "scan"
	ActionDryRun  EngineAction = "dry-run"
	ActionRewrite EngineAction = "rewrite"
)

const engineScript = "clean-secret-from-repos.sh"

// FindEngine locates the cleanup engine script. An explicit path wins;
// otherwise the executable's directory, its parent, and the working
// directory are searched.
func FindEngine(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("engine script not found: %s", explicit)
		}
		return explicit, nil
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, engineScript),
			filepath.Join(dir, "..", engineScript),
		)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, engineScript),
			filepath.Join(cwd, "..", engineScript),
		)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return filepath.Abs(c)
		}
	}
	return "", fmt.Errorf("%s not found next to the binary or working directory; pass --engine", engineScript)
}

// BuildEngineCmd writes the secrets to a private temporary key file and
// prepares the engine invocation over the given repositories. The returned
// cleanup function removes the key file and must be called once the command
// has finished.
func BuildEngineCmd(engine string, action EngineAction, secrets []string, repos []string) (*exec.Cmd, func(), error) {
	if len(secrets) == 0 {
		return nil, nil, fmt.Errorf("no recovered secrets to clean")
	}
	keyFile, err := os.CreateTemp("", "secretsweep-keys-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.Remove(keyFile.Name()) }
	if err := keyFile.Chmod(0o600); err != nil {
		keyFile.Close()
		cleanup()
		return nil, nil, err
	}
	for _, s := range secrets {
		// The engine treats ** as a mask and a leading literal: as a marker,
		// so exact keys are always written in literal form.
		if _, err := fmt.Fprintf(keyFile, "literal:%s\n", s); err != nil {
			keyFile.Close()
			cleanup()
			return nil, nil, err
		}
	}
	if err := keyFile.Close(); err != nil {
		cleanup()
		return nil, nil, err
	}

	args := []string{engine, "--" + string(action), "--no-color", "--no-recurse", "--key-file", keyFile.Name()}
	if action == ActionRewrite {
		args = append(args, "--yes")
	}
	args = append(args, repos...)
	return exec.Command("bash", args...), cleanup, nil
}
