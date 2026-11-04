package router

import "net/http"

func ProjectHosts(platformOrigin string, operator, project http.Handler) http.Handler {
	if project == nil {
		return operator
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if "https://"+r.Host == platformOrigin {
			operator.ServeHTTP(w, r)
			return
		}
		project.ServeHTTP(w, r)
	})
}
