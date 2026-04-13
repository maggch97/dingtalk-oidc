package oidc

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestTransformClaimsIncludesRedirectURIContext(t *testing.T) {
	s := &Server{
		ClaimsTransformScript: `
function transform(claims, context) {
	claims.redirect_uri = context.redirect_uri;
	claims.callback_url = context.callback_url;
	return claims;
}
`,
	}

	transformed, err := s.transformClaims(jwt.MapClaims{
		"sub": "user-123",
	}, map[string]any{
		"redirect_uri": "https://app.example.com/callback",
		"callback_url": "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("transformClaims returned error: %v", err)
	}

	if got := transformed["redirect_uri"]; got != "https://app.example.com/callback" {
		t.Fatalf("redirect_uri = %v, want %q", got, "https://app.example.com/callback")
	}
	if got := transformed["callback_url"]; got != "https://app.example.com/callback" {
		t.Fatalf("callback_url = %v, want %q", got, "https://app.example.com/callback")
	}
}
