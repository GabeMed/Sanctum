package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GabeMed/Sanctum/internal/domain"
	"github.com/GabeMed/Sanctum/internal/service"
	"github.com/google/uuid"
)

const testToken = "test-token-0123456789"

// stubService records calls and returns canned results.
type stubService struct {
	createErr  error
	listErr    error
	getErr     error
	gotContent string
	gotDay     *time.Time
	listed     []domain.ReflectionOutput
	byID       domain.ReflectionOutput
}

var sample = domain.ReflectionOutput{
	ID:        uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
	Day:       time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC),
	Content:   "Today I understood that patience is not passive...",
	CreatedAt: time.Date(2026, 3, 4, 8, 30, 0, 0, time.UTC),
}

func (s *stubService) Create(_ context.Context, content string) (domain.ReflectionOutput, error) {
	s.gotContent = content
	if s.createErr != nil {
		return domain.ReflectionOutput{}, s.createErr
	}
	out := sample
	out.Content = content
	return out, nil
}

func (s *stubService) ListByDay(_ context.Context, day *time.Time) ([]domain.ReflectionOutput, error) {
	s.gotDay = day
	return s.listed, s.listErr
}

func (s *stubService) GetByID(_ context.Context, id uuid.UUID) (domain.ReflectionOutput, error) {
	if s.getErr != nil {
		return domain.ReflectionOutput{}, s.getErr
	}
	return s.byID, nil
}

func newServer(t *testing.T, svc *stubService) http.Handler {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	mux := http.NewServeMux()
	h := NewReflectionHandler(svc)
	h.now = func() time.Time { return sample.CreatedAt }
	h.Register(mux, RequireToken(testToken))
	return mux
}

func do(t *testing.T, srv http.Handler, method, path, body string, authorized bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authorized {
		req.Header.Set("Authorization", "Bearer "+testToken)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("response is not valid JSON: %v\n%s", err, rec.Body.String())
	}
	return v
}

func TestCreate_Created(t *testing.T) {
	svc := &stubService{}
	rec := do(t, newServer(t, svc), "POST", "/v1/reflections", `{"content":"hello"}`, true)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	got := decode[reflectionResponse](t, rec)
	want := reflectionResponse{
		ID:        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		Day:       "2026-03-04",
		Content:   "hello",
		CreatedAt: "2026-03-04T08:30:00Z",
	}
	if got != want {
		t.Errorf("body = %+v, want %+v", got, want)
	}
	if svc.gotContent != "hello" {
		t.Errorf("service received %q", svc.gotContent)
	}
}

func TestCreate_BadInput(t *testing.T) {
	cases := map[string]string{
		"not json":       `content=hello`,
		"wrong type":     `{"content": 42}`,
		"unknown field":  `{"content":"x","day":"2026-01-01"}`,
		"two objects":    `{"content":"x"}{"content":"y"}`,
		"empty body":     ``,
		"too large body": `{"content":"` + strings.Repeat("a", MaxBodyBytes) + `"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(t, newServer(t, &stubService{}), "POST", "/v1/reflections", body, true)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if e := decode[errorResponse](t, rec); e.Error != "invalid_input" {
				t.Fatalf("error code = %q", e.Error)
			}
		})
	}
}

func TestCreate_EmptyContent(t *testing.T) {
	svc := &stubService{createErr: service.ErrEmptyContent}
	rec := do(t, newServer(t, svc), "POST", "/v1/reflections", `{"content":"  "}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestInternalErrorsDoNotLeak(t *testing.T) {
	secret := errors.New("pq: password authentication failed for user sanctum")
	svc := &stubService{createErr: secret, listErr: secret, getErr: secret}
	srv := newServer(t, svc)

	for _, rec := range []*httptest.ResponseRecorder{
		do(t, srv, "POST", "/v1/reflections", `{"content":"x"}`, true),
		do(t, srv, "GET", "/v1/reflections", "", true),
		do(t, srv, "GET", "/v1/reflections/"+sample.ID.String(), "", true),
	} {
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "password") {
			t.Fatalf("internal error leaked: %s", rec.Body)
		}
		if e := decode[errorResponse](t, rec); e.Error != "internal" {
			t.Fatalf("error code = %q", e.Error)
		}
	}
}

func TestList(t *testing.T) {
	svc := &stubService{listed: []domain.ReflectionOutput{sample}}
	srv := newServer(t, svc)

	rec := do(t, srv, "GET", "/v1/reflections?day=2026-03-04", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decode[listResponse](t, rec)
	if body.Count != 1 || len(body.Reflections) != 1 || body.Reflections[0].Day != "2026-03-04" {
		t.Fatalf("body = %+v", body)
	}
	if svc.gotDay == nil || !svc.gotDay.Equal(sample.Day) {
		t.Fatalf("service received day %v", svc.gotDay)
	}

	do(t, srv, "GET", "/v1/reflections", "", true)
	if svc.gotDay != nil {
		t.Fatalf("no day filter should pass nil, got %v", svc.gotDay)
	}
}

func TestList_EmptyIsArray(t *testing.T) {
	rec := do(t, newServer(t, &stubService{}), "GET", "/v1/reflections", "", true)
	if !strings.Contains(rec.Body.String(), `"reflections":[]`) || !strings.Contains(rec.Body.String(), `"count":0`) {
		t.Fatalf("body = %s", rec.Body)
	}
}

func TestList_InvalidDay(t *testing.T) {
	for _, day := range []string{"04-03-2026", "2026-13-01", "yesterday"} {
		rec := do(t, newServer(t, &stubService{}), "GET", "/v1/reflections?day="+day, "", true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("day=%s: status = %d, want 400", day, rec.Code)
		}
	}
}

func TestGetByID(t *testing.T) {
	svc := &stubService{byID: sample}
	rec := do(t, newServer(t, svc), "GET", "/v1/reflections/"+sample.ID.String(), "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := decode[reflectionResponse](t, rec); got.ID != sample.ID.String() || got.Content != sample.Content {
		t.Fatalf("body = %+v", got)
	}
}

func TestGetByID_Errors(t *testing.T) {
	notFound := &stubService{getErr: domain.ErrNotFound}
	if rec := do(t, newServer(t, notFound), "GET", "/v1/reflections/"+uuid.NewString(), "", true); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: status = %d, want 404", rec.Code)
	}
	if rec := do(t, newServer(t, &stubService{}), "GET", "/v1/reflections/not-a-uuid", "", true); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id: status = %d, want 400", rec.Code)
	}
}

func TestAuth(t *testing.T) {
	srv := newServer(t, &stubService{})
	routes := []struct{ method, path, body string }{
		{"POST", "/v1/reflections", `{"content":"x"}`},
		{"GET", "/v1/reflections", ""},
		{"GET", "/v1/reflections/" + sample.ID.String(), ""},
	}
	headers := map[string]string{
		"missing":      "",
		"wrong token":  "Bearer not-the-token",
		"no scheme":    testToken,
		"basic scheme": "Basic " + testToken,
		"prefix only":  "Bearer " + testToken[:5],
	}
	for _, route := range routes {
		for name, header := range headers {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s (%s): status = %d, want 401", route.method, route.path, name, rec.Code)
			}
		}
	}
}

func TestHealth_NoAuth(t *testing.T) {
	rec := do(t, newServer(t, &stubService{}), "GET", "/v1/health", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	got := decode[map[string]string](t, rec)
	if got["status"] != "healthy" || got["timestamp"] != "2026-03-04T08:30:00Z" {
		t.Fatalf("body = %v", got)
	}
}

func TestAppendOnly_NoUpdateOrDelete(t *testing.T) {
	srv := newServer(t, &stubService{})
	for _, method := range []string{"PUT", "PATCH", "DELETE"} {
		rec := do(t, srv, method, "/v1/reflections/"+sample.ID.String(), `{}`, true)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, rec.Code)
		}
	}
}

func TestLogRequests_RecordsStatus(t *testing.T) {
	var logged strings.Builder
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	h := LogRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x?secret=1", nil))
	if !strings.Contains(logged.String(), "GET /x 418") || strings.Contains(logged.String(), "secret") {
		t.Fatalf("log line = %q", logged.String())
	}
}
