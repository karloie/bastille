# Builder: build a static bastille binary
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY

WORKDIR /src
COPY go.mod go.sum ./
COPY app app
RUN mkdir -p /out && CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags "-s -w \
    -X main.Version=${VERSION} \
    -X main.GitCommit=${GIT_COMMIT} \
    -X main.BuildTime=${BUILD_TIME}" \
    -o /out/bastille ./app


FROM alpine:3.23
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/bastille /usr/local/bin/bastille
RUN addgroup -g 10001 bastille && adduser -D -u 10001 -G bastille bastille && mkdir -p /hostkeys /home /ca && chown -R bastille:bastille /hostkeys /home /ca
USER bastille

EXPOSE 22222/tcp
ENTRYPOINT ["/usr/local/bin/bastille"]
