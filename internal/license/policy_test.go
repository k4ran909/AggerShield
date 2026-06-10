package license

import (
	"path/filepath"
	"testing"

	"aggershield/internal/config"
)

func TestApplyToOverlaysOnlySetFields(t *testing.T) {
	base := &config.Config{Upstream: "http://app:3000"}
	base.RateLimit.PerIPRPS = 20
	base.Challenge.Secret = "local-secret"

	dryRun := true
	doc := &PolicyDoc{
		DryRun: &dryRun,
		Rules:  &[]config.Rule{{Name: "block-admin", PathPrefix: "/wp-admin", Action: "block"}},
	}
	doc.ApplyTo(base)

	if !base.DryRun {
		t.Fatal("DryRun should be overlaid")
	}
	if len(base.Rules) != 1 || base.Rules[0].Name != "block-admin" {
		t.Fatalf("Rules not overlaid: %+v", base.Rules)
	}
	// Untouched fields stay as they were.
	if base.Upstream != "http://app:3000" || base.RateLimit.PerIPRPS != 20 {
		t.Fatal("unset policy fields must not change base config")
	}
}

func TestApplyToPreservesChallengeSecret(t *testing.T) {
	base := &config.Config{}
	base.Challenge.Secret = "keep-me"
	ch := config.Challenge{Enabled: true, Mode: "always"} // no secret in pushed policy
	doc := &PolicyDoc{Challenge: &ch}
	doc.ApplyTo(base)
	if base.Challenge.Secret != "keep-me" {
		t.Fatalf("challenge secret must be preserved, got %q", base.Challenge.Secret)
	}
	if !base.Challenge.Enabled || base.Challenge.Mode != "always" {
		t.Fatal("challenge policy fields should be applied")
	}
}

func TestPolicyStoreVersioning(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "lic.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := s.Generate("svc", "")

	if doc, ver := s.Policy(key.ID); doc != nil || ver != 0 {
		t.Fatal("no policy should exist initially")
	}
	dr := true
	v1, _ := s.SetPolicy(key.ID, &PolicyDoc{DryRun: &dr})
	v2, _ := s.SetPolicy(key.ID, &PolicyDoc{DryRun: &dr})
	if v1 != 1 || v2 != 2 {
		t.Fatalf("version should increment: got %d, %d", v1, v2)
	}

	// Persisted across reload.
	s2, _ := Open(filepath.Join(t.TempDir(), "lic.json"))
	_, k2, _ := s2.Generate("svc2", "")
	_, _ = s2.SetPolicy(k2.ID, &PolicyDoc{DryRun: &dr})
	s3, err := Open(s2.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ver := s3.Policy(k2.ID); ver != 1 {
		t.Fatalf("policy version should persist, got %d", ver)
	}
}
