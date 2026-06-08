// Package challenge implements a stateless proof-of-work (PoW) browser
// challenge — AggerShield's defence against distributed botnets.
//
// Why it matters: per-IP rate limiting is blind to a botnet that keeps every
// individual IP under the limit. A challenge changes the economics: every
// client must spend CPU to compute a hash with N leading zero bits before it
// is served. A real browser does this invisibly in ~1s; a dumb flood client
// that doesn't execute JavaScript can never pass, so it is filtered out
// regardless of how many IPs it spreads across.
//
// Statelessness: we never store issued challenges. The challenge parameters
// (random token, timestamp, difficulty) are HMAC-signed with a server secret
// and handed to the client. The solved clearance cookie echoes those signed
// params plus the nonce, so the server can verify everything from the cookie
// alone:
//
//  1. HMAC matches  -> we really issued these params (client can't pick an
//     easier difficulty).
//  2. Not expired   -> within ClearanceTTL of the issued timestamp.
//  3. PoW valid     -> SHA-256(token:nonce) has >= difficulty leading zero bits.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	clearanceCookie = "ag_clearance"
	// Header advertised on challenge responses so non-browser clients (and
	// our own demo solver) can detect and machine-read the challenge.
	HeaderChallenge = "X-AggerShield-Challenge"
	HeaderData      = "X-AggerShield-Challenge-Data" // "token.ts.difficulty.sig"
)

// Manager issues and verifies PoW challenges. Difficulty and clearance TTL
// are atomic so they can be tuned at runtime (hot-reload); the signing secret
// is fixed for the process lifetime (changing it would invalidate live
// clearances).
type Manager struct {
	secret       []byte
	difficulty   atomic.Int64 // leading zero bits required
	clearanceTTL atomic.Int64 // nanoseconds
}

// New builds a Manager. If secret is empty a random one is generated, which
// means clearances reset whenever the process restarts.
func New(secret string, difficultyBits int, clearanceTTL time.Duration) *Manager {
	key := []byte(secret)
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	m := &Manager{secret: key}
	m.SetParams(difficultyBits, clearanceTTL)
	return m
}

// SetParams updates the PoW difficulty and clearance lifetime at runtime.
func (m *Manager) SetParams(difficultyBits int, clearanceTTL time.Duration) {
	m.difficulty.Store(int64(difficultyBits))
	m.clearanceTTL.Store(int64(clearanceTTL))
}

func (m *Manager) diff() int          { return int(m.difficulty.Load()) }
func (m *Manager) ttl() time.Duration { return time.Duration(m.clearanceTTL.Load()) }

// HasClearance reports whether the request carries a valid clearance cookie.
func (m *Manager) HasClearance(r *http.Request) bool {
	ck, err := r.Cookie(clearanceCookie)
	if err != nil {
		return false
	}
	return m.verify(ck.Value)
}

// Serve writes a PoW challenge response: a small HTML page whose embedded
// JavaScript solves the puzzle and sets the clearance cookie, plus headers
// that let non-browser clients read the challenge parameters.
func (m *Manager) Serve(w http.ResponseWriter, _ *http.Request) {
	token := randHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	difficulty := m.diff()
	diff := strconv.Itoa(difficulty)
	sig := m.sign(token, ts, diff)

	w.Header().Set(HeaderChallenge, "1")
	w.Header().Set(HeaderData, strings.Join([]string{token, ts, diff, sig}, "."))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 200 so browsers reliably render the body and run the script.
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, challengeHTML, token, ts, difficulty, sig, int(m.ttl().Seconds()))
}

// verify validates a clearance cookie value of form "token.ts.diff.nonce.sig".
func (m *Manager) verify(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 5 {
		return false
	}
	token, ts, diff, nonce, sig := parts[0], parts[1], parts[2], parts[3], parts[4]

	// 1. Signature: proves we issued these params (constant-time compare).
	if !hmac.Equal([]byte(sig), []byte(m.sign(token, ts, diff))) {
		return false
	}
	// 2. Expiry.
	issued, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(issued, 0)) > m.ttl() {
		return false
	}
	// 3. Proof of work.
	d, err := strconv.Atoi(diff)
	if err != nil {
		return false
	}
	return PoWValid(token, nonce, d)
}

// sign returns the hex HMAC-SHA256 over the challenge parameters.
func (m *Manager) sign(token, ts, diff string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(token + "|" + ts + "|" + diff))
	return hex.EncodeToString(mac.Sum(nil))
}

// PoWValid reports whether SHA-256("token:nonce") has at least difficulty
// leading zero bits. Exported so the demo solver can reuse the exact rule.
func PoWValid(token, nonce string, difficulty int) bool {
	sum := sha256.Sum256([]byte(token + ":" + nonce))
	return LeadingZeroBits(sum[:]) >= difficulty
}

// LeadingZeroBits counts leading zero bits across a byte slice.
func LeadingZeroBits(b []byte) int {
	c := 0
	for _, x := range b {
		if x == 0 {
			c += 8
			continue
		}
		return c + bits.LeadingZeros8(x)
	}
	return c
}

func randHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// challengeHTML is the interstitial page. The synchronous-feeling loop yields
// to the event loop periodically so the browser stays responsive. crypto.subtle
// requires a secure context (HTTPS or localhost) — serve AggerShield over TLS
// in production.
const challengeHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser…</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:18vh auto;padding:0 1rem;color:#222}
.sp{display:inline-block;width:1rem;height:1rem;border:2px solid #ccc;border-top-color:#444;border-radius:50%%;animation:s 1s linear infinite;vertical-align:-2px}
@keyframes s{to{transform:rotate(360deg)}}</style></head>
<body>
<h2>🛡️ Checking your browser before continuing…</h2>
<p><span class="sp"></span> <span id="st">Solving a one-time security puzzle. This takes a moment and requires no action from you.</span></p>
<noscript>This site requires JavaScript to verify your browser.</noscript>
<script>
(async function(){
  var C=%q,TS=%q,D=%d,SIG=%q,MAXAGE=%d;
  var enc=new TextEncoder(), st=document.getElementById('st');
  function lz(u){var c=0;for(var i=0;i<u.length;i++){var b=u[i];if(b===0){c+=8;continue;}var bits=0,v=b;while(bits<8&&(v&128)===0){bits++;v=(v<<1)&255;}return c+bits;}return c;}
  for(var n=0;;n++){
    var h=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(C+":"+n)));
    if(lz(h)>=D){
      document.cookie="ag_clearance="+[C,TS,D,n,SIG].join(".")+";path=/;max-age="+MAXAGE+";SameSite=Lax";
      location.reload();return;
    }
    if(n%%2000===0){st.textContent="Verifying… ("+n+" attempts)";await new Promise(function(r){setTimeout(r,0);});}
  }
})();
</script>
</body></html>`
