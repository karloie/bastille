# Builder: build a static bastille binary
FROM golang:1.26-alpine AS builder

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd cmd
COPY pkg pkg
RUN mkdir -p /out && CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags "-s -w \
    -X main.Version=${BUILD_VERSION} \
    -X main.GitCommit=${BUILD_COMMIT} \
    -X main.BuildTime=${BUILD_DATE}" \
    -o /out/bastille ./cmd/bastille


FROM alpine:3.23
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/bastille /usr/local/bin/bastille
RUN addgroup -g 10001 bastille && adduser -D -u 10001 -G bastille bastille && mkdir -p /hostkeys /home /ca && chown -R bastille:bastille /hostkeys /home /ca
USER bastille

EXPOSE 22222/tcp
ENTRYPOINT ["/usr/local/bin/bastille"]
