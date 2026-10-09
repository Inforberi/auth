package router

import "net/http"

// @Summary Legacy process ping
// @Tags Health
// @Produce plain
// @Success 200 {string} string "pong"
// @Router /ping [get]
func ping(w http.ResponseWriter, _ *http.Request) {
	if _, err := w.Write([]byte("pong")); err != nil {
		return
	}
}
