FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

# 在容器根目录创建 src 目录
WORKDIR /src

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk update \
 && apk add --no-cache g++ git

COPY ./go.mod .

COPY ./go.sum .

ENV GOPROXY="https://goproxy.cn"

RUN go mod tidy \
 && go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLE=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o auto-cert ./main.go

FROM alpine:latest

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
 && apk add --no-cache tzdata

WORKDIR /app

COPY --from=builder /src/auto-cert /app/
COPY --from=builder /src/config.yaml /app/config.yaml

ENTRYPOINT ["./auto-cert"]
