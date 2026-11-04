package auth

import "context"

type testApplication struct {
	resources *Resources
	serve     func(context.Context) error
}

func (a *testApplication) Run(ctx context.Context) error { defer a.Close(); return a.serve(ctx) }
func (a *testApplication) Close()                        { a.resources.Close() }
