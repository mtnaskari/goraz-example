# The image holds the program and CA certificates, and nothing else: no shell, no
# secrets. The goraz service file and its key are mounted at run time.
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -o /out/orders ./cmd/orders

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/orders /orders
USER 65532:65532
EXPOSE 8088
ENTRYPOINT ["/orders"]
