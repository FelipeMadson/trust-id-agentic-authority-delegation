FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /trust-id-server ./cmd/server

FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

COPY --from=builder /trust-id-server .

EXPOSE 8084

ENTRYPOINT ["./trust-id-server"]
