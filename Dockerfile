FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /hub .

FROM alpine:3.24
# git: template sources; docker-cli(+compose): app lifecycle via host socket
RUN apk add --no-cache ca-certificates git docker-cli docker-cli-compose
COPY --from=build /hub /usr/local/bin/hub
ENTRYPOINT ["hub"]
