package service_test

import (
	"strings"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
)

var testActor = accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
