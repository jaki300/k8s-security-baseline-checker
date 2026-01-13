# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build CLI
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-checker ./cmd/cli

# Build server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-checker-server ./cmd/server

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binaries
COPY --from=builder /build/k8s-checker /build/k8s-checker-server ./
COPY --from=builder /build/benchmarks ./benchmarks

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser && \
    chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["./k8s-checker"]

