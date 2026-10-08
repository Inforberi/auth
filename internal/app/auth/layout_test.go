package auth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPackageBoundaries(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			if ast.IsGenerated(file) {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			for _, im := range file.Imports {
				dep, err := strconv.Unquote(im.Path.Value)
				if err != nil {
					return err
				}
				checkDependency(t, filepath.ToSlash(rel), dep)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func checkDependency(t *testing.T, path, dep string) {
	t.Helper()
	const module = "github.com/Inforberi/financial-intelligence/"
	local := strings.TrimPrefix(dep, module)
	for _, old := range []string{"internal/core/", "internal/featers/", "internal/modules/", "internal/app/config", "internal/infra/httpserver"} {
		if strings.HasPrefix(local, old) {
			t.Errorf("%s imports removed package %s", path, dep)
		}
	}
	if strings.HasSuffix(path, "_test.go") {
		return
	}
	business := strings.HasPrefix(local, "internal/auth/") ||
		strings.HasPrefix(local, "internal/access/") ||
		strings.HasPrefix(local, "internal/entitlement/") ||
		strings.HasPrefix(local, "internal/billing/") ||
		strings.HasPrefix(local, "internal/audit/")
	if (strings.HasPrefix(path, "internal/infra/") || strings.HasPrefix(path, "internal/server/")) &&
		(business || strings.HasPrefix(local, "internal/app/") || strings.HasPrefix(local, "internal/config/")) {
		t.Errorf("%s: technical component imports application/business package %s", path, dep)
	}
	if strings.Contains(path, "/domain/") {
		if strings.HasPrefix(local, "internal/") && !strings.Contains(local, "/domain") {
			t.Errorf("%s: domain imports implementation %s", path, dep)
		}
		if strings.Contains(dep, "/pgx/") || strings.Contains(dep, "/go-redis/") || dep == "net/http" || dep == "database/sql" {
			t.Errorf("%s: domain imports storage/HTTP %s", path, dep)
		}
	}
	if strings.Contains(path, "/service/") &&
		(strings.Contains(local, "/repository/") || strings.Contains(local, "/transport/") ||
			strings.HasPrefix(local, "internal/infra/") || strings.HasPrefix(local, "internal/integrations/") ||
			strings.HasPrefix(local, "internal/app/") || strings.HasPrefix(local, "internal/server/") ||
			strings.HasPrefix(local, "internal/config/")) {
		t.Errorf("%s: service imports concrete adapter %s", path, dep)
	}
	if strings.Contains(path, "/transport/") && strings.Contains(local, "/repository/") {
		t.Errorf("%s: transport bypasses service via %s", path, dep)
	}
}
