package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type installation struct {
	Name, Origin, SMTPHost, SMTPFrom string
	SMTPPort                         uint
}

var (
	projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	relayHost   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

func (i installation) validate() error {
	if !projectName.MatchString(i.Name) {
		return errors.New("invalid Compose project name")
	}
	if strings.ContainsAny(i.Origin, "\r\n\t $'\",") || (middleware.OriginConfig{AllowedOrigins: []string{i.Origin}}).Validate() != nil {
		return errors.New("provide an exact HTTPS origin")
	}
	sender, err := mail.ParseAddress(i.SMTPFrom)
	if err != nil || sender.Address != i.SMTPFrom || strings.ContainsAny(i.SMTPFrom, "\r\n\t $'\\\"#") ||
		!relayHost.MatchString(i.SMTPHost) || i.SMTPPort == 0 || i.SMTPPort > 65535 {
		return errors.New("provide a trusted SMTP relay, port and plain sender address")
	}
	return nil
}

func writeBundle(dir string, input installation) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return checkBundle(dir, input)
		}
		return err
	}

	files, err := bundleFiles(input)
	if err != nil {
		return err
	}
	for _, name := range []string{"storage.env", "runtime.env", "runtime-role.sql", "installation.json"} {
		if err := publishFile(dir, name, files[name]); err != nil {
			return err
		}
	}
	return nil
}

func checkBundle(dir string, input installation) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("installation directory is not private")
	}
	for _, name := range []string{"storage.env", "runtime.env", "runtime-role.sql", "installation.json"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() == 0 || info.Size() > 16384 {
			return errors.New("installation bundle is incomplete or unsafe; recover it before retrying")
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	b, err := root.ReadFile("installation.json")
	err = errors.Join(err, root.Close())
	if err != nil {
		return err
	}
	var stored installation
	if json.Unmarshal(b, &stored) != nil || stored != input {
		return errors.New("installation parameters differ from the existing bundle")
	}
	return nil
}

func bundleFiles(i installation) (map[string][]byte, error) {
	owner, runtime, redis := randomSecret(), randomSecret(), randomSecret()
	migration := databaseURL("auth_owner", owner)
	app := databaseURL("auth_runtime", runtime)
	domain := i.SMTPFrom[strings.LastIndex(i.SMTPFrom, "@")+1:]
	manifest, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"installation.json": manifest,
		"storage.env":       []byte(fmt.Sprintf("APP_NAME=%s\nPOSTGRES_DB=auth\nPOSTGRES_USER=auth_owner\nPOSTGRES_PASSWORD=%s\nMIGRATION_DATABASE_URL=%s\nREDIS_PASSWORD=%s\n", i.Name, owner, migration, redis)),
		"runtime.env": []byte(fmt.Sprintf("APP_ENV=prod\nAUTH_SETTINGS_MODE=api\nAUTH_INSTALL_CLOSED_PROFILE=true\nAUTH_ALLOWED_ORIGINS=%s\nDATABASE_URL=%s\nREDIS_HOST=redis\nREDIS_PASSWORD=%s\nEMAIL_OUTBOX_KEY=%s\nINITIAL_SETUP_ENABLED=true\nINITIAL_SETUP_SECRET=%s\nMFA_ENABLED=true\nSMTP_REQUIRE_TLS=true\nSMTP_HOST=%s\nSMTP_PORT=%d\nSMTP_FROM=%s\nSMTP_DOMAIN=%s\nPASSWORD_RESET_TOKEN_TTL=1h\nPASSWORD_RESET_URL=%s/reset-password\nEMAIL_VERIFICATION_URL=%s/verify-email\n",
			i.Origin, app, redis, base64.StdEncoding.EncodeToString(randBytes()), randomSecret(), i.SMTPHost, i.SMTPPort, i.SMTPFrom, domain, i.Origin, i.Origin)),
		"runtime-role.sql": []byte(fmt.Sprintf("DO $$ BEGIN\nIF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='auth_runtime') THEN\nCREATE ROLE auth_runtime LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nEND IF;\nEND $$;\n", runtime)),
	}, nil
}

func databaseURL(user, password string) string {
	return (&url.URL{Scheme: "postgres", User: url.UserPassword(user, password), Host: net.JoinHostPort("postgres", "5432"), Path: "/auth", RawQuery: "sslmode=disable"}).String()
}

func randBytes() []byte {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return buf
}

func randomSecret() string {
	return base64.RawURLEncoding.EncodeToString(randBytes())
}

func publishFile(dir, name string, data []byte) (err error) {
	tmp, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.Remove(tmp.Name())) }()
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), filepath.Join(dir, name))
}
