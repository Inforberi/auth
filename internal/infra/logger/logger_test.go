package logger

import "testing"

func TestProductionLogSampling(t *testing.T) {
	production := loggerConfig(Config{Env: "prod", Level: "info"})
	if production.Sampling == nil || production.Sampling.Initial != 100 || production.Sampling.Thereafter != 100 {
		t.Fatal("production log storm protection missing")
	}
	if loggerConfig(Config{Env: "dev", Level: "debug"}).Sampling != nil {
		t.Fatal("development diagnostics were sampled")
	}
}
