FROM golang:alpine

WORKDIR /auth-service
COPY . .

RUN go mod tidy && \
    go build -o auth-service ./cmd/auth-service/main.go

CMD ["./auth-service"]