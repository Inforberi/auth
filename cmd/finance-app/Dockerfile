FROM golang:1.26.2-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/finance-app \
    ./cmd/finance-app


FROM alpine:3.23.4

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app \
    && adduser -S app -G app

COPY --from=builder /out/finance-app ./finance-app

USER app

EXPOSE 8080

CMD ["./finance-app"]