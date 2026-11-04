package secretbox

import "github.com/Inforberi/financial-intelligence/internal/infra/realmscope"

func ForScope(scope realmscope.Scope, root, purpose string) (*Cipher, error) {
	context, err := scope.Purpose(purpose)
	if err != nil {
		return nil, err
	}
	return NewScoped(root, context)
}
