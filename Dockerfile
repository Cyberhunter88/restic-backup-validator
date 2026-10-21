FROM golang:1.27.3-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/validator ./cmd/validator

FROM alpine:3.24
LABEL org.opencontainers.image.source="https://github.com/Cyberhunter88/restic-backup-validator"
RUN apk add --no-cache ca-certificates openssh-client restic rclone tzdata && \
    addgroup -S -g 10001 validator && adduser -S -D -H -u 10001 -G validator validator && \
    mkdir -p /data && chown validator:validator /data
COPY --from=build /out/validator /usr/local/bin/validator
USER 10001:10001
ENV HOME=/data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/validator"]
