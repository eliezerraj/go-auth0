#docker build -t go-auth0 .
#docker run -dit --name go-auth0 -p 5100:5100 go-auth0

FROM golang:1.22 As builder

RUN apt-get update && apt-get install bash && apt-get install -y --no-install-recommends ca-certificates

WORKDIR /app
COPY . .

WORKDIR /app/cmd
RUN go build -o go-auth0 -ldflags '-linkmode external -w -extldflags "-static"'

FROM alpine

WORKDIR /app
COPY --from=builder /app/cmd/go-auth0 .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/cmd/vault/private_key.pem /app/cmd/vault/
COPY --from=builder /app/cmd/vault/public_key.pem /app/cmd/vault/

CMD ["/app/go-auth0"]