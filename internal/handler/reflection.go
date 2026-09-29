// Package handler exposes the reflection service over HTTP, following the API
// contract in docs/rfc.md section 3. It knows nothing about AES-GCM or SQL.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/GabeMed/Sanctum/internal/domain"
	"github.com/GabeMed/Sanctum/internal/service"
	"github.com/google/uuid"
)

// MaxBodyBytes caps the size of a POST /v1/reflections request body.
const MaxBodyBytes = 64 << 10 // 64 KiB

// ReflectionService is what the handler needs from the service layer.
type ReflectionService interface {
	Create(ctx context.Context, content string) (domain.ReflectionOutput, error)
	ListByDay(ctx context.Context, day *time.Time) ([]domain.ReflectionOutput, error)
	GetByID(ctx context.Context, id uuid.UUID) (domain.ReflectionOutput, error)
}

// ReflectionHandler serves /v1/reflections.
type ReflectionHandler struct {
	service ReflectionService
	now     func() time.Time
}

// NewReflectionHandler returns a handler backed by svc.
func NewReflectionHandler(svc ReflectionService) *ReflectionHandler {
	return &ReflectionHandler{service: svc, now: time.Now}
}

// Register adds the routes to mux. auth wraps every /v1/reflections route;
// /v1/health is left unauthenticated.
func (h *ReflectionHandler) Register(mux *http.ServeMux, auth func(http.Handler) http.Handler) {
	mux.Handle("POST /v1/reflections", auth(http.HandlerFunc(h.handleCreate)))
	mux.Handle("GET /v1/reflections", auth(http.HandlerFunc(h.handleList)))
	mux.Handle("GET /v1/reflections/{id}", auth(http.HandlerFunc(h.handleGetByID)))
	mux.HandleFunc("GET /v1/health", h.handleHealth)
}

type createRequest struct {
	Content string `json:"content"`
}

type reflectionResponse struct {
	ID        string `json:"id"`
	Day       string `json:"day"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
}

type listResponse struct {
	Reflections []reflectionResponse `json:"reflections"`
	Count       int                  `json:"count"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (h *ReflectionHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var req createRequest
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "request body must be a JSON object with a \"content\" string")
		return
	}
	if decoder.More() {
		writeError(w, http.StatusBadRequest, "invalid_input", "request body must contain a single JSON object")
		return
	}

	out, err := h.service.Create(r.Context(), req.Content)
	if errors.Is(err, service.ErrEmptyContent) {
		writeError(w, http.StatusBadRequest, "invalid_input", "content must not be empty")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toResponse(out))
}

func (h *ReflectionHandler) handleList(w http.ResponseWriter, r *http.Request) {
	var day *time.Time
	if raw := r.URL.Query().Get("day"); raw != "" {
		parsed, err := time.Parse(time.DateOnly, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_input", "day must be formatted as YYYY-MM-DD")
			return
		}
		day = &parsed
	}

	outs, err := h.service.ListByDay(r.Context(), day)
	if err != nil {
		internalError(w, r, err)
		return
	}
	resp := listResponse{Reflections: make([]reflectionResponse, 0, len(outs)), Count: len(outs)}
	for _, out := range outs {
		resp.Reflections = append(resp.Reflections, toResponse(out))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *ReflectionHandler) handleGetByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "id must be a UUID")
		return
	}

	out, err := h.service.GetByID(r.Context(), id)
	if errors.Is(err, domain.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "reflection not found")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toResponse(out))
}

func (h *ReflectionHandler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":    "healthy",
		"timestamp": h.now().UTC().Format(time.RFC3339),
	})
}

func toResponse(out domain.ReflectionOutput) reflectionResponse {
	return reflectionResponse{
		ID:        out.ID.String(),
		Day:       out.Day.Format(time.DateOnly),
		Content:   out.Content,
		CreatedAt: out.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// internalError logs the real error server-side and returns a generic 500.
func internalError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("internal error on %s %s: %v", r.Method, r.URL.Path, err)
	writeError(w, http.StatusInternalServerError, "internal", "internal server error")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("encode response: %v", err)
	}
}
