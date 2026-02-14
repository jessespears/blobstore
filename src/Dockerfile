FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN go build -o blobstore .

FROM alpine:latest
RUN apk add --no-cache fortune
COPY --from=build /app/blobstore /blobstore
EXPOSE 8080
CMD ["/blobstore"]
