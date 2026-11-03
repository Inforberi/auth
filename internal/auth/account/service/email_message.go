package service

type EmailMessage struct {
	To      string `json:"to"`
	Link    string `json:"link"`
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
}
