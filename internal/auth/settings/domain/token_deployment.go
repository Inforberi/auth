package domain

// TokenDeployment describes this instance's loaded configuration, not a mutable SQL policy.
type TokenDeployment struct {
	Enabled              bool
	NativeEnabled        bool
	IntrospectionEnabled bool
	Issuer               string
	AccessTTLSeconds     int64
	Resources            []TokenResource
}

type TokenResource struct {
	Audience    string
	Mode        string
	Permissions []string
}
