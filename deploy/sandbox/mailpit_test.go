package sandbox_test

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"testing"
	"time"
)

func invitationMailToken(t *testing.T, email string, previous ...string) string {
	t.Helper()
	transport := &http.Transport{MaxConnsPerHost: 2, IdleConnTimeout: 15 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var page struct{ Messages []struct{ ID string } }
		mailpitJSON(t, ctx, client, "/api/v1/search?limit=2&query="+url.QueryEscape("to:"+email), &page)
		for _, entry := range page.Messages {
			var message struct {
				HTML string
				To   []struct{ Address string }
			}
			mailpitJSON(t, ctx, client, "/api/v1/message/"+url.PathEscape(entry.ID), &message)
			matched := false
			for _, recipient := range message.To {
				matched = matched || recipient.Address == email
			}
			if !matched {
				t.Fatal("Mailpit search returned an unrelated recipient")
			}
			for _, href := range regexp.MustCompile(`href="([^"]+)"`).FindAllStringSubmatch(message.HTML, -1) {
				link, err := url.Parse(html.UnescapeString(href[1]))
				if err != nil || link.Scheme != "https" || link.Host != "localhost:18443" || link.Path != "/activate-account" {
					continue
				}
				fragment, err := url.ParseQuery(link.Fragment)
				if err == nil && fragment.Get("token") != "" && !slices.Contains(previous, fragment.Get("token")) {
					return fragment.Get("token")
				}
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
	}
	t.Fatal("invitation did not arrive in Mailpit with a valid frontend link")
	return ""
}

func mailpitJSON(t *testing.T, ctx context.Context, client *http.Client, path string, output any) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:18026"+path, nil)
	if err != nil {
		t.Fatal("invalid Mailpit request")
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("Mailpit request failed")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 262145))
	if err != nil || len(data) > 262144 || response.StatusCode != 200 || json.Unmarshal(data, output) != nil {
		t.Fatal("invalid or oversized Mailpit response")
	}
}
