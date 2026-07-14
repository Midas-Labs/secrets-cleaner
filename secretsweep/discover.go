package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DiscoverRepos returns the Git repositories found at or below each target
// path. A target that is itself a repository (working clone, worktree, or
// bare/mirror) is included directly; folders are searched recursively.
// Results are absolute, deduplicated, and in discovery order.
func DiscoverRepos(targets []string) ([]string, error) {
	seen := map[string]bool{}
	var repos []string
	add := func(path string) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		if !seen[abs] {
			seen[abs] = true
			repos = append(repos, abs)
		}
	}

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			return nil, fmt.Errorf("target does not exist: %s", target)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("target is not a folder: %s", target)
		}
		if pathIsRepo(target) {
			add(target)
		}
		walkErr := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			name := d.Name()
			if name == ".git" {
				add(filepath.Dir(path))
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() && strings.HasSuffix(name, ".git") && isBareRepo(path) {
				add(path)
				return fs.SkipDir
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	return repos, nil
}

func pathIsRepo(path string) bool {
	if info, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		_ = info
		return true
	}
	return isBareRepo(path)
}

func isBareRepo(path string) bool {
	out, err := exec.Command("git", "-C", path, "rev-parse", "--is-bare-repository").Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}
