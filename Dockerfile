# Build stage
FROM golang:1.19.1-alpine3.16 as build

ARG SHOWCERT_VERSION=latest

RUN apk update && apk add --no-cache git
RUN go env -w GOPROXY=direct

RUN mkdir /project
WORKDIR /project
ADD . /project

RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o showcert -ldflags="-s -w -X 'showcert/internal/cli.Version=${SHOWCERT_VERSION}'" showcert/cmd/showcert

RUN addgroup -S appgroup && adduser -S showcert -G appgroup

# copy artifacts to a scratch image
FROM scratch
COPY --from=build /etc/passwd /etc/passwd
USER showcert
COPY --from=build /project/showcert /showcert
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT [ "/showcert" ]
CMD ["--help"]