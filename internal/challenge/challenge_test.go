package challenge

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// issueAndSolve drives the full client flow: get a challenge, find a valid
// nonce, and build the clearance cookie value.
func issueAndSolve(t *testing.T, m *Manager) (cookieVal, data string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Serve(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	data = rec.Header().Get(HeaderData)
	parts := strings.Split(data, ".")
	if len(parts) != 4 {
		t.Fatalf("challenge data malformed: %q", data)
	}
	token, ts, diffStr, sig := parts[0], parts[1], parts[2], parts[3]
	diff, _ := strconv.Atoi(diffStr)

	nonce := ""
	for n := 0; n < 1<<24; n++ {
		if PoWValid(token, strconv.Itoa(n), diff) {
			nonce = strconv.Itoa(n)
			break
		}
	}
	if nonce == "" {
		t.Fatal("failed to solve PoW")
	}
	return strings.Join([]string{token, ts, diffStr, nonce, sig}, "."), data
}

func reqWithCookie(val string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: clearanceCookie, Value: val})
	return r
}

func TestSolvedChallengeGrantsClearance(t *testing.T) {
	m := New("test-secret", 10, time.Minute) // 10 bits solves fast
	cookieVal, _ := issueAndSolve(t, m)
	if !m.HasClearance(reqWithCookie(cookieVal)) {
		t.Fatal("a correctly solved challenge should grant clearance")
	}
}

func TestNoCookieNoClearance(t *testing.T) {
	m := New("test-secret", 10, time.Minute)
	if m.HasClearance(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("a request with no clearance cookie must not pass")
	}
}

func TestTamperedDifficultyRejected(t *testing.T) {
	m := New("test-secret", 12, time.Minute)
	cookieVal, _ := issueAndSolve(t, m)
	// Attacker lowers the difficulty field but keeps the original signature.
	parts := strings.Split(cookieVal, ".")
	parts[2] = "1" // claim difficulty 1
	if m.HasClearance(reqWithCookie(strings.Join(parts, "."))) {
		t.Fatal("lowering the signed difficulty must invalidate the cookie")
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	m := New("test-secret", 10, time.Minute)
	cookieVal, _ := issueAndSolve(t, m)
	parts := strings.Split(cookieVal, ".")
	parts[4] = strings.Repeat("0", len(parts[4])) // bogus signature
	if m.HasClearance(reqWithCookie(strings.Join(parts, "."))) {
		t.Fatal("a forged signature must be rejected")
	}
}

func TestExpiredClearanceRejected(t *testing.T) {
	m := New("test-secret", 10, time.Nanosecond) // immediate expiry
	cookieVal, _ := issueAndSolve(t, m)
	time.Sleep(time.Millisecond)
	if m.HasClearance(reqWithCookie(cookieVal)) {
		t.Fatal("an expired clearance must be rejected")
	}
}
