// Command flood is a DEMO/TEST load generator for AggerShield. It is NOT an
// attack tool: it only targets a URL you control and works by setting the
// X-Forwarded-For header so a single local machine can simulate many source
// IPs (AggerShield must trust 127.0.0.1 as a proxy for this to take effect).
//
// Modes:
//
//	single      — all requests appear to come from one IP. You should see
//	              200s (burst), then 429 (rate limited), then 403 (banned).
//	distributed — each request appears to come from a unique IP, simulating a
//	              botnet. Per-IP limits never trip, so the GLOBAL limiter is
//	              what sheds the excess (503 Service busy).
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aggershield/internal/challenge"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8080/", "target URL (must be yours)")
	mode := flag.String("mode", "single", "single | distributed")
	n := flag.Int("n", 300, "total requests")
	c := flag.Int("c", 20, "concurrency")
	ip := flag.String("ip", "203.0.113.7", "simulated source IP for single mode")
	solve := flag.Bool("solve", false, "act like a real browser: solve PoW challenges and retry")
	flag.Parse()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 200,
		},
	}

	var (
		counts sync.Map // status code -> *int64
		done   int64
	)
	bump := func(code int) {
		v, _ := counts.LoadOrStore(code, new(int64))
		atomic.AddInt64(v.(*int64), 1)
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < *c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				srcIP := *ip
				if *mode == "distributed" {
					srcIP = randIP()
				}
				code, chalData := doRequest(client, *url, srcIP, "")

				// If challenged and we're emulating a real browser, solve the
				// PoW and retry with the resulting clearance cookie.
				if *solve && code == codeChallenge && chalData != "" {
					if cookie := solveChallenge(chalData); cookie != "" {
						code, _ = doRequest(client, *url, srcIP, cookie)
					}
				}
				bump(code)
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	start := time.Now()
	for i := 0; i < *n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("\nFlood complete: mode=%s requests=%d concurrency=%d elapsed=%s (%.0f req/s)\n",
		*mode, *n, *c, elapsed.Round(time.Millisecond), float64(*n)/elapsed.Seconds())
	fmt.Println("Status code distribution:")

	var codes []int
	counts.Range(func(k, _ any) bool { codes = append(codes, k.(int)); return true })
	sort.Ints(codes)
	for _, code := range codes {
		v, _ := counts.Load(code)
		fmt.Printf("  %-3s : %d\n", label(code), atomic.LoadInt64(v.(*int64)))
	}
}

// codeChallenge is a synthetic status used to bucket "served a PoW challenge".
const codeChallenge = -1

func label(code int) string {
	switch code {
	case 0:
		return "ERR"
	case codeChallenge:
		return "CHL"
	}
	return fmt.Sprintf("%d", code)
}

// doRequest performs one request as srcIP (via X-Forwarded-For), optionally
// sending a clearance cookie. It returns the status code (or codeChallenge if
// the response was a PoW challenge) and the challenge data when present.
func doRequest(client *http.Client, url, srcIP, cookie string) (code int, chalData string) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Forwarded-For", srcIP)
	// Look like a browser navigation so the (default html-only) challenge gate
	// applies — this is what a botnet hammering your site looks like.
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	if resp.Header.Get(challenge.HeaderChallenge) == "1" {
		return codeChallenge, resp.Header.Get(challenge.HeaderData)
	}
	return resp.StatusCode, ""
}

// solveChallenge mirrors the browser JS: given "token.ts.diff.sig" it finds a
// nonce satisfying the PoW and returns a ready-to-send clearance cookie.
func solveChallenge(data string) string {
	parts := strings.Split(data, ".")
	if len(parts) != 4 {
		return ""
	}
	token, ts, diffStr, sig := parts[0], parts[1], parts[2], parts[3]
	diff, err := strconv.Atoi(diffStr)
	if err != nil {
		return ""
	}
	for n := 0; n < 1<<28; n++ {
		nonce := strconv.Itoa(n)
		if challenge.PoWValid(token, nonce, diff) {
			val := strings.Join([]string{token, ts, diffStr, nonce, sig}, ".")
			return "ag_clearance=" + val
		}
	}
	return ""
}

func randIP() string {
	// 198.18.0.0/15 is the IANA benchmarking range — safe to use for demos,
	// never routes to a real host. ~65k unique addresses to simulate a botnet.
	return fmt.Sprintf("198.18.%d.%d", rand.Intn(256), rand.Intn(254)+1)
}
