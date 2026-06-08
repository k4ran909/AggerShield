package rules

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"aggershield/internal/config"
)

func match(t *testing.T, s *Set, method, path string) Decision {
	t.Helper()
	return s.Match(httptest.NewRequest(method, path, nil))
}

func TestFirstMatchWins(t *testing.T) {
	s, err := Compile([]config.Rule{
		{Name: "block-admin", PathPrefix: "/admin", Action: "block"},
		{Name: "allow-all", PathPrefix: "/", Action: "allow"},
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if d := match(t, s, http.MethodGet, "/admin/users"); d.Action != ActionBlock {
		t.Fatalf("/admin should block, got %v", d.Action)
	}
	if d := match(t, s, http.MethodGet, "/public"); d.Action != ActionAllow {
		t.Fatalf("/public should hit allow-all, got %v", d.Action)
	}
}

func TestMethodAndRegexMatch(t *testing.T) {
	s, err := Compile([]config.Rule{
		{Name: "post-login", PathRegex: `^/login$`, Methods: []string{"POST"}, Action: "challenge"},
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if d := match(t, s, http.MethodPost, "/login"); d.Action != ActionChallenge {
		t.Fatalf("POST /login should challenge, got %v", d.Action)
	}
	if d := match(t, s, http.MethodGet, "/login"); d.Action != ActionDefault {
		t.Fatalf("GET /login should fall through to default, got %v", d.Action)
	}
	if d := match(t, s, http.MethodPost, "/login/extra"); d.Action != ActionDefault {
		t.Fatalf("regex anchored, /login/extra should not match, got %v", d.Action)
	}
}

func TestRateOverrideAttachesLimiter(t *testing.T) {
	s, err := Compile([]config.Rule{
		{Name: "tight-checkout", PathPrefix: "/checkout", Action: "", PerIPRPS: 2},
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d := match(t, s, http.MethodGet, "/checkout/pay")
	if d.Limiter == nil {
		t.Fatal("expected a route-specific limiter for /checkout")
	}
}

func TestBadRegexErrors(t *testing.T) {
	if _, err := Compile([]config.Rule{{Name: "bad", PathRegex: "([", Action: "block"}}, 1000); err == nil {
		t.Fatal("expected an error compiling an invalid regex")
	}
}
