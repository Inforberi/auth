package deploy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeGrantsIdentifiers(t *testing.T) {
	sql := RuntimeGrants(`project"db`, `runtime"role`)
	require.Contains(t, sql, `GRANT CONNECT ON DATABASE "project""db" TO "runtime""role"`)
	require.Contains(t, sql, `REVOKE INSERT, UPDATE, DELETE ON auth.restore_audit FROM "runtime""role"`)
	for line := range strings.SplitSeq(sql, "\n") {
		if !strings.HasPrefix(line, "--") {
			require.NotContains(t, line, "auth_runtime")
		}
	}
}
