package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"time"
)

// RequireToken returns middleware that accepts only requests carrying
// "Authorization: Bearer <token>". Both values are hashed before the
// constant-time comparison so the check does not leak the token length.
func RequireToken(token string) func(http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			got := sha256.Sum256([]byte(presented))
			if !ok || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="sanctum"`)
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid API token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LogRequests logs method, path, status and duration of every request.
// It never logs bodies or headers.
func LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Microsecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}
