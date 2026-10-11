package hasher

import (
	"encoding/base64"
	"strconv"
	"strings"
)

type parameters struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func parse(encoded string) (parameters, error) {
	var p parameters
	if len(encoded) > 4096 {
		return p, ErrInvalidHashFormat
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return p, ErrInvalidHashFormat
	}
	memory, cost, threads, err := parseCosts(parts[3])
	if err != nil {
		return p, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || base64.RawStdEncoding.EncodeToString(salt) != parts[4] {
		return p, ErrInvalidHashFormat
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || base64.RawStdEncoding.EncodeToString(key) != parts[5] {
		return p, ErrInvalidHashFormat
	}
	if len(salt) < 8 || len(salt) > 64 || len(key) < 16 || len(key) > 256 {
		return p, ErrInvalidHashFormat
	}
	p.memory, p.time, p.threads = uint32(memory), uint32(cost), uint8(threads) //nolint:gosec // parseCosts bounds memory to 262144, cost to 10 and threads to 32.
	p.salt, p.key = salt, key
	return p, nil
}

func (a *Argon2idHash) NeedsRehash(encoded string) bool {
	p, err := parse(encoded)
	if err != nil {
		return false
	}
	// Не заменяем более дорогой профиль более дешёвым автоматически.
	if p.memory > a.memory || p.time > a.time {
		return false
	}
	return p.memory < a.memory || p.time < a.time || len(p.salt) < int(a.saltLen) || len(p.key) < int(a.keyLen)
}

func parseCosts(encoded string) (uint64, uint64, uint64, error) {
	fields := strings.Split(encoded, ",")
	if len(fields) != 3 {
		return 0, 0, 0, ErrInvalidHashFormat
	}
	var values [3]uint64
	for i, prefix := range []string{"m=", "t=", "p="} {
		value, ok := strings.CutPrefix(fields[i], prefix)
		if !ok || value == "" {
			return 0, 0, 0, ErrInvalidHashFormat
		}
		for _, c := range value {
			if c < '0' || c > '9' {
				return 0, 0, 0, ErrInvalidHashFormat
			}
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, 0, 0, ErrInvalidHashFormat
		}
		values[i] = n
	}
	memory, cost, threads := values[0], values[1], values[2]
	if threads < 1 || threads > 32 || memory < 8*threads || memory > 256*1024 || cost < 1 || cost > 10 {
		return 0, 0, 0, ErrInvalidHashFormat
	}
	return memory, cost, threads, nil
}
