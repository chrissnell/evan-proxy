FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /evan-proxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
    && apk del --purge apk-tools \
    && rm -rf /var/cache/apk/* /sbin/apk /etc/apk /lib/apk /usr/share/apk \
    && addgroup -g 10001 -S proxy \
    && adduser -u 10001 -S -G proxy -H -s /sbin/nologin proxy \
    && rm -rf /tmp/* /var/tmp/*
USER 10001:10001
COPY --from=build /evan-proxy /evan-proxy
ENTRYPOINT ["/evan-proxy"]
