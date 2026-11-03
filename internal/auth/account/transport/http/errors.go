package accounthttp

import (
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func Unavailable() httpx.Failure {
	return httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"}
}
