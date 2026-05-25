package core_http

type Handlers struct {
	Register *register_http.Handler
}

func New(h Handlers)
