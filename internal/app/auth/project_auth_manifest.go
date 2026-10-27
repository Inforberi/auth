package auth

import (
	"errors"
	"io"
	"os"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/jsonconfig"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

var errProjectAuthManifest = errors.New("invalid project auth deployment manifest")

type projectAuthManifest struct {
	Version  int                       `json:"version"`
	Projects []projectMethodDeployment `json:"projects"`
}

type projectMethodDeployment struct {
	ID                projectdomain.ID         `json:"id"`
	Browser           bool                     `json:"browser"`
	Invitations       bool                     `json:"invitations"`
	TemporaryPassword bool                     `json:"temporaryPassword"`
	Access            *projectAccessDeployment `json:"access,omitempty"`
	AuthSettings      bool                     `json:"authSettings"`
	UserLifecycle     bool                     `json:"userLifecycle"`
	UserDirectory     bool                     `json:"userDirectory"`
	EmailOTP          bool                     `json:"emailOTP"`
	Reauthentication  bool                     `json:"reauthentication"`
	EmailBinding      bool                     `json:"emailBinding"`
	EmailChange       bool                     `json:"emailChange"`
	Google            bool                     `json:"google"`
	Telegram          bool                     `json:"telegram"`
	JWT               *projectJWTDeployment    `json:"jwt,omitempty"`
}

type projectJWTDeployment struct {
	Native      bool                                     `json:"native"`
	Password    bool                                     `json:"password"`
	Permissions []accesssettings.Permission              `json:"permissions"`
	Resources   []tokenservice.Resource                  `json:"resources"`
	Clients     []tokenservice.IntrospectionClientConfig `json:"clients,omitempty"`
}

func loadProjectAuthManifest(path string) (manifest projectAuthManifest, resultErr error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return manifest, errProjectAuthManifest
	}
	file, err := os.Open(path) //nolint:gosec // Deployment-owned configuration, never a request path.
	if err != nil {
		return manifest, errProjectAuthManifest
	}
	defer func() {
		if file.Close() != nil {
			manifest, resultErr = projectAuthManifest{}, errProjectAuthManifest
		}
	}()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return manifest, errProjectAuthManifest
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || jsonconfig.Decode(data, &manifest) != nil {
		return projectAuthManifest{}, errProjectAuthManifest
	}
	if err := validateProjectAuthManifest(manifest); err != nil {
		return projectAuthManifest{}, err
	}
	return manifest, nil
}

func validateProjectAuthManifest(manifest projectAuthManifest) error {
	if manifest.Version != 1 || manifest.Projects == nil {
		return errProjectAuthManifest
	}
	seen := make(map[projectdomain.ID]bool)
	for _, entry := range manifest.Projects {
		if !projectdomain.ValidID(entry.ID) || seen[entry.ID] || !validProjectMethodDeployment(entry) {
			return errProjectAuthManifest
		}
		seen[entry.ID] = true
	}
	return nil
}

func validProjectMethodDeployment(entry projectMethodDeployment) bool {
	if !entry.Browser && entry.requiresBrowser() {
		return false
	}
	if entry.EmailBinding && !entry.Reauthentication {
		return false
	}
	native := entry.JWT != nil && entry.JWT.Native
	if entry.EmailOTP && !entry.Browser && !native {
		return false
	}
	return entry.JWT == nil || !entry.JWT.Password || native
}

type projectAccessDeployment struct {
	Permissions []accesssettings.Permission `json:"permissions"`
}

func (entry projectMethodDeployment) requiresBrowser() bool {
	return entry.Reauthentication || entry.Google || entry.Telegram ||
		entry.EmailBinding || entry.EmailChange || entry.AuthSettings ||
		entry.Access != nil || entry.UserDirectory || entry.UserLifecycle ||
		entry.Invitations || entry.TemporaryPassword
}
