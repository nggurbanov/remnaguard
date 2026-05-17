# RemnaGuard is not affiliated with, endorsed by, or sponsored by Remnawave.
FROM golang:1.26.3-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates tzdata
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/remnaguard ./cmd/remnaguard

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -u 10001 remnaguard
COPY --from=build /out/remnaguard /usr/local/bin/remnaguard
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["remnaguard"]
CMD ["serve", "-c", "/etc/remnaguard/remnaguard.yaml"]
