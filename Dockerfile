FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ipban ./main.go

FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
    && addgroup -S app \
    && adduser -S -G app app

WORKDIR /app

COPY --from=builder /out/ipban /app/ipban
COPY --from=builder /src/static /app/static

RUN mkdir -p /app/data && chown -R app:app /app

USER app

ENV GIN_MODE=release
ENV DB_PATH=/app/data/ipban.db
ENV PORT=8080

VOLUME ["/app/data"]
EXPOSE 8080

ENTRYPOINT ["/app/ipban"]
