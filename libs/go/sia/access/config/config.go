package config

// Role models the configuration to be specified in sia_config
type Role struct {
	Service string   `json:"service,omitempty"`    // principal service with role access
	Roles   []string `json:"roles,omitempty"`      // the roles in the domain in which principal is a member
	Expiry  int      `json:"expires_in,omitempty"` // requested expiry time for access token in seconds
}

// AccessToken is the type that holds information AFTER processing the configuration
type AccessToken struct {
	FileName string   // FileName under /var/lib/sia/tokens
	Service  string   // Principal service that is a member of the roles
	Domain   string   // Domain in which principal is a member of
	Roles    []string // Roles under the Domain for which access tokens are being requested
	User     string   // Owner of the access token file on disc
	Uid      int      // Uid of the Owner of file on disc
	Gid      int      // Gid of the file on disc
	Expiry   int      // Expiry of the access token
}

// TokenOptions holds all the configurable options for driving Access Tokens functionality
type TokenOptions struct {
	Domain    string        // Domain of the instance
	Services  []string      // Services set on the instance
	TokenDir  string        // Directory where tokens will be saved, typically /var/lib/sia/tokens
	Tokens    []AccessToken // List of Access Tokens with their configuration
	CertDir   string        // Directory where certs can be found, typically /var/lib/sia/certs
	KeyDir    string        // Directory where keys can be found, typically /var/lib/sia/keys
	ZtsUrl    string        // ZTS endpoint
	UserAgent string        // User Agent string to be sent in the client call to ZTS, typically a client version
}
