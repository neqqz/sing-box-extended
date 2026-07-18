FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
LABEL maintainer="shtorm-7"
COPY . /go/src/github.com/sagernet/sing-box
WORKDIR /go/src/github.com/sagernet/sing-box
ARG TARGETOS TARGETARCH
ARG GOPROXY=""
ARG CRONET_GO_PATH=/go/src/github.com/sagernet/sing-box/cronet-go
ENV GOPROXY=${GOPROXY}
ENV CGO_ENABLED=1
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
ENV CRONET_GO_PATH=${CRONET_GO_PATH}
RUN set -ex \
    && git config --global --add safe.directory /go/src/github.com/sagernet/sing-box \
    && export GOTOOLCHAIN=local \
    && export CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    && eval "$(CGO_ENABLED=0 GOOS= GOARCH= go run -C "$CRONET_GO_PATH" ./cmd/build-naive --target=$GOOS/$GOARCH --libc=musl env --export)" \
    && export CGO_LDFLAGS="$CGO_LDFLAGS -Wl,-z,notext -Wl,-z,execstack" \
    && export VERSION=$(CGO_ENABLED=0 GOOS= GOARCH= go run ./cmd/internal/read_tag) \
    && export TAGS=$(cat release/DEFAULT_BUILD_TAGS_DOCKER) \
    && export LDFLAGS_SHARED=$(cat release/LDFLAGS) \
    && go build -v -trimpath -tags "$TAGS" \
        -o /go/bin/sing-box \
        -ldflags "-X \"github.com/sagernet/sing-box/constant.Version=$VERSION\" $LDFLAGS_SHARED -s -w -buildid=" \
        ./cmd/sing-box
FROM --platform=$TARGETPLATFORM alpine AS dist
LABEL maintainer="shtorm-7"
RUN set -ex \
    && apk add --no-cache --upgrade bash tzdata ca-certificates nftables
COPY --from=builder /go/bin/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
