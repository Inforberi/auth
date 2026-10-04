# Legacy entry point retained for compatibility. Canonical production build:
# docker build -f deploy/Dockerfile.prod .
ARG GO_IMAGE=golang:1.27.1-bookworm
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -o /out/auth ./cmd/auth
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/auth /app/auth
ENTRYPOINT ["/app/auth"]
