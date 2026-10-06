package templates

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net/url"
	"time"
)

//go:embed reset_password_header.html
var resetHeader string

//go:embed reset_password_content.html
var resetContent string

// Concatenate before parsing so HTML escaping keeps the complete document context.
var resetHTML = resetHeader + resetContent

type ResetPasswordData struct {
	UserName  string
	ResetURL  string
	ExpiresIn string
	Year      int
	Company   string
}

func RenderResetPassword(baseURL, token string, ttl time.Duration, now time.Time) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" || token == "" || ttl <= 0 {
		return "", fmt.Errorf("invalid password reset configuration")
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	tmpl, err := template.New("reset_password").Parse(resetHTML)
	if err != nil {
		return "", fmt.Errorf("parse password reset template: %w", err)
	}
	var body bytes.Buffer
	err = tmpl.Execute(&body, ResetPasswordData{ResetURL: u.String(), ExpiresIn: ttl.String(), Year: now.Year(), Company: "Auth"})
	if err != nil {
		return "", fmt.Errorf("render password reset template: %w", err)
	}
	return body.String(), nil
}
