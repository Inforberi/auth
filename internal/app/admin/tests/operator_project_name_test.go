package admin_test

import (
	"net/http"
	"testing"
)

func checkProjectRename(t *testing.T, h *operatorHTTPS, id string, session *http.Cookie) {
	t.Helper()
	path := "/api/v1/platform/projects/" + id + "/name"
	cookies := []*http.Cookie{session}
	body := map[string]any{
		"operationId":     "81999999-9999-4999-8999-999999999999",
		"expectedVersion": 2,
		"name":            " Updated project ",
		"reason":          "fixture-name",
	}
	result, _ := h.call("POST", path, body, cookies, 200)
	if operatorField(t, result, "name") != "Updated project" || string(result["version"]) != "3" {
		t.Fatal("incorrect renamed project receipt")
	}
	replay, _ := h.call("POST", path, body, cookies, 200)
	if string(replay["replayed"]) != "true" || string(replay["version"]) != "3" {
		t.Fatal("rename replay did not return original receipt")
	}
	body["name"] = "Different project"
	h.call("POST", path, body, cookies, 409)
	card, _ := h.call("GET", "/api/v1/platform/projects/"+id, nil, cookies, 200)
	if operatorField(t, card, "name") != "Updated project" || operatorField(t, card, "slug") != "new-project" ||
		string(card["generation"]) != "2" {
		t.Fatal("rename changed the project binding")
	}
}
