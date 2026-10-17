package http

import (
	"cmp"
	"slices"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type TokenResourceResponse struct {
	Audience    string   `json:"audience"`
	Mode        string   `json:"mode" enums:"strict,local"`
	Permissions []string `json:"permissions"`
	Revocation  string   `json:"revocation" enums:"online,token_expiry"`
} // @name auth_settings_http.TokenResourceResponse

type TokenProfilesResponse struct {
	ManagedBy              string                  `json:"managedBy" enums:"deployment"`
	Scope                  string                  `json:"scope" enums:"instance"`
	ChangesRequireRollout  bool                    `json:"changesRequireRollout"`
	BrowserAdminTransport  string                  `json:"browserAdminTransport" enums:"cookie"`
	JWTEnabled             bool                    `json:"jwtEnabled"`
	SessionExchangeEnabled bool                    `json:"sessionExchangeEnabled"`
	NativeEnabled          bool                    `json:"nativeEnabled"`
	IntrospectionEnabled   bool                    `json:"introspectionEnabled"`
	Issuer                 string                  `json:"issuer"`
	AccessTTLSeconds       int64                   `json:"accessTtlSeconds"`
	Resources              []TokenResourceResponse `json:"resources"`
} // @name auth_settings_http.TokenProfilesResponse

func tokenProfilesResponse(deployment domain.TokenDeployment) TokenProfilesResponse {
	response := TokenProfilesResponse{ManagedBy: "deployment", Scope: "instance", ChangesRequireRollout: true, BrowserAdminTransport: "cookie", Resources: []TokenResourceResponse{}}
	if !deployment.Enabled {
		return response
	}
	response.JWTEnabled, response.SessionExchangeEnabled = true, true
	response.NativeEnabled, response.IntrospectionEnabled = deployment.NativeEnabled, deployment.IntrospectionEnabled
	response.Issuer, response.AccessTTLSeconds = deployment.Issuer, deployment.AccessTTLSeconds
	for _, resource := range deployment.Resources {
		revocation := "online"
		if resource.Mode == authjwt.Local {
			revocation = "token_expiry"
		}
		permissions := slices.Clone(resource.Permissions)
		slices.Sort(permissions)
		response.Resources = append(response.Resources, TokenResourceResponse{Audience: resource.Audience, Mode: resource.Mode, Permissions: permissions, Revocation: revocation})
	}
	slices.SortFunc(response.Resources, func(a, b TokenResourceResponse) int { return cmp.Compare(a.Audience, b.Audience) })
	return response
}
