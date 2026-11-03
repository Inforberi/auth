package mfahttp

import (
	"time"
)

type RecoveryCodesResponse struct {
	Codes []string `json:"codes"`
} // @name mfa_http.RecoveryCodesResponse

type StatusResponse struct {
	Status string `json:"status"`
} // @name mfa_http.StatusResponse

type EnrollmentResponse struct {
	Token     string    `json:"token"`
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfa_http.EnrollmentResponse
