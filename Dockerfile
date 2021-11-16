# Copyright 2021 Adevinta

FROM golang:1.17-alpine3.14 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN GOOS=linux GOARCH=amd64 go build .

FROM docker:20.10.11-alpine3.14

ARG BUILD_RFC3339="1970-01-01T00:00:00Z"
ARG COMMIT="local"

ENV BUILD_RFC3339 "$BUILD_RFC3339"
ENV COMMIT "$COMMIT"

RUN apk add git

WORKDIR /app

COPY --from=builder /app/vulcan-local .

ENTRYPOINT [ "/app/vulcan-local" ]
