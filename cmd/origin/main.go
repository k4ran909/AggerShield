// Command origin is a trivial backend used for demos: it represents the
// application AggerShield protects. It just returns 200 with a short body.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":3000", "listen address")
	name := flag.String("name", "origin", "identifier returned in responses")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Echo back routing-relevant details so demos can show host routing,
		// preserve_host, and the forwarded client IP.
		fmt.Fprintf(w, "origin=%s host=%s path=%s x-real-ip=%s ja3=%s ja4=%s\n",
			*name, r.Host, r.URL.Path, r.Header.Get("X-Real-IP"),
			r.Header.Get("X-AggerShield-JA3"), r.Header.Get("X-AggerShield-JA4"))
	})

	log.Printf("origin %q listening on %s", *name, *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}
