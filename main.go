package traefikroleguard

import (
	"context"
	"net/http"
	"strings"
)

type Config struct {
	RequiredRole string `json:"requiredRole,omitempty"`
}

func CreateConfig() *Config {
	return &Config{RequiredRole: "USER"}
}

type RoleGuard struct {
	next					http.Handler
	name					string
	requiredRole	string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &RoleGuard{
		next:         next,
		name:         name,
		requiredRole: config.RequiredRole,
	}, nil
}

func (rg *RoleGuard) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rolesHeader := req.Header.Get("X-Forwarded-Roles")
	if rolesHeader == "" {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	roles := strings.Split(rolesHeader, ",")
	for i := range roles {
		if strings.TrimSpace(roles[i]) == rg.requiredRole {
			rg.next.ServeHTTP(rw, req)
			return
		}
	}

	http.Error(rw, "Forbidden", http.StatusForbidden)
}

