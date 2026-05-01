# syntax=docker/dockerfile:1.6

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/modsec-exporter ./cmd/modsec-exporter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/modsec-exporter /usr/local/bin/modsec-exporter
EXPOSE 9555
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/modsec-exporter"]
