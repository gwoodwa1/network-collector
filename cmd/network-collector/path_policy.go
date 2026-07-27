package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func canonicalRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "."
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func resolveReadWithin(root, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", fmt.Errorf("path cannot be empty")
	}
	if filepath.IsAbs(requested) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	resolvedRoot, err := canonicalRoot(root)
	if err != nil {
		return "", fmt.Errorf("resolve permitted root: %w", err)
	}
	candidate, err := filepath.EvalSymlinks(filepath.Join(resolvedRoot, requested))
	if err != nil {
		return "", err
	}
	candidate = filepath.Clean(candidate)
	if !pathWithin(resolvedRoot, candidate) {
		return "", fmt.Errorf("path %q escapes permitted root %q", requested, resolvedRoot)
	}
	return candidate, nil
}

func resolveWriteWithin(root, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", fmt.Errorf("path cannot be empty")
	}
	if filepath.IsAbs(requested) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	resolvedRoot, err := canonicalRoot(root)
	if err != nil {
		return "", fmt.Errorf("resolve permitted root: %w", err)
	}
	candidate := filepath.Clean(filepath.Join(resolvedRoot, requested))
	if !pathWithin(resolvedRoot, candidate) {
		return "", fmt.Errorf("path %q escapes permitted root %q", requested, resolvedRoot)
	}

	ancestor := filepath.Dir(candidate)
	for {
		_, statErr := os.Lstat(ancestor)
		if statErr == nil {
			break
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", fmt.Errorf("no existing parent for path %q", requested)
		}
		ancestor = parent
	}
	resolvedAncestor, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", err
	}
	if !pathWithin(resolvedRoot, filepath.Clean(resolvedAncestor)) {
		return "", fmt.Errorf("path %q traverses a symlink outside permitted root %q", requested, resolvedRoot)
	}
	return candidate, nil
}
