package app_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestSourceLayout keeps the agreed structure in the ordinary test workflow.
func TestSourceLayout(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || (!strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".html")) {
				return nil
			}
			checkSource(t, root, path)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func checkSource(t *testing.T, root, path string) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file *ast.File
	if strings.HasSuffix(path, ".go") {
		file, err = parser.ParseFile(token.NewFileSet(), path, src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if ast.IsGenerated(file) {
			return
		}
	}
	lines := bytes.Count(src, []byte("\n"))
	if len(src) > 0 && src[len(src)-1] != '\n' {
		lines++
	}
	if lines > 150 {
		t.Errorf("%s: %d lines, maximum 150; split by responsibility", path, lines)
	}
	if file == nil {
		return
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatal(err)
	}
	rel = filepath.ToSlash(rel)
	for _, im := range file.Imports {
		dep, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		checkDependency(t, rel, dep)
	}
}

func checkDependency(t *testing.T, path, dep string) {
	t.Helper()
	const module = "github.com/Inforberi/financial-intelligence/"
	local := strings.TrimPrefix(dep, module)
	if strings.HasPrefix(local, "internal/core/") || strings.HasPrefix(local, "internal/featers/") {
		t.Errorf("%s imports removed package %s", path, dep)
	}
	if strings.HasPrefix(path, "internal/infra/") && strings.HasPrefix(local, "internal/modules/") {
		t.Errorf("%s: infrastructure must not depend on a business feature", path)
	}
	if !strings.HasPrefix(path, "internal/modules/auth/") || strings.HasSuffix(path, "_test.go") {
		return
	}
	if strings.Contains(path, "/model/") && (strings.HasPrefix(local, "internal/") && !strings.Contains(local, "/model")) {
		t.Errorf("%s: model imports implementation %s", path, dep)
	}
	if strings.Contains(path, "/service/") && (strings.Contains(local, "/repository/") || strings.Contains(local, "/transport/") || strings.HasPrefix(local, "internal/infra/") || strings.HasPrefix(local, "internal/integrations/") || strings.HasPrefix(local, "internal/app/")) {
		t.Errorf("%s: service imports concrete adapter %s", path, dep)
	}
}
