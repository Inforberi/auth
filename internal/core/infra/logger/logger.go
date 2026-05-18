package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func CreateLogger(cfg Config) *zap.Logger {
	encoderCfg := zap.NewProductionEncoderConfig()
	development := cfg.Env == "dev"
	encoding := "json"

	if development {
		encoderCfg = zap.NewDevelopmentEncoderConfig()
		encoding = "console"
	}

	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	config := zap.Config{
		Level:             zap.NewAtomicLevelAt(getConfigLevel(cfg.Level)),
		Development:       development,
		DisableCaller:     false,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          encoding,
		EncoderConfig:     encoderCfg,
		OutputPaths: []string{
			"stdout",
		},
		ErrorOutputPaths: []string{
			"stdout",
		},
		InitialFields: map[string]any{
			"pid": os.Getpid(),
		},
	}

	return zap.Must(config.Build())
}

func getConfigLevel(lvl string) zapcore.Level {
	levelStr := strings.ToLower(strings.TrimSpace(lvl))

	switch levelStr {
	case "debug":
		return zap.DebugLevel
	case "info":
		return zap.InfoLevel
	case "warn":
		return zap.WarnLevel
	case "error":
		return zap.ErrorLevel
	case "dpanic":
		return zap.DPanicLevel
	case "panic":
		return zap.PanicLevel
	case "fatal":
		return zap.FatalLevel
	default:
		return zap.InfoLevel
	}
}
