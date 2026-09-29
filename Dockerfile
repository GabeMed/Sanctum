# Build stage: static binary, no cgo.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sanctum ./cmd/server

# Runtime stage: distroless, no shell, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sanctum /sanctum
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/sanctum"]
