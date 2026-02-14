FROM golang:1.21-alpine AS build
WORKDIR /app
COPY go.mod ./
COPY *.go ./
RUN go build -o blobstore .

FROM alpine:latest
RUN apk add --no-cache fortune
COPY --from=build /app/blobstore /blobstore
EXPOSE 8080
CMD ["/blobstore"]
