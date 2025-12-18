FROM golang:bookworm AS builder
RUN go install github.com/mitranim/gow@latest
EXPOSE 22222
WORKDIR /app
CMD [ "gow", "run", "*.go" ]
