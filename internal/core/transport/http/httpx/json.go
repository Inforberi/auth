package httpx

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Code    string `json:"code" example:"invalid_json"`
	Message string `json:"message" example:"invalid json"`
}

func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, ErrorResponse{
		Code:    code,
		Message: message,
	})
}
