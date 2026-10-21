ARG BUILD_IMAGE=golang:1.27.3-trixie@sha256:604106102d33b1084e37ca08adf98ac0813624ae8595bd0d7f3965ecebded09c
ARG DAEMON_IMAGE=debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e
ARG POSTFIX_IMAGE=chrroessner/postfix@sha256:736180b4fa352bb55bdca9e93e9201c7df7a419dad6622ed601d9dde028ae254

FROM ${BUILD_IMAGE} AS build
ENV GOEXPERIMENT=runtimesecret
ENV GOTOOLCHAIN=go1.27.3
WORKDIR /source
COPY go.work go.work.sum ./
COPY lib ./lib
COPY cmd/dkim2d ./cmd/dkim2d
COPY cmd/dkim2-milter ./cmd/dkim2-milter
COPY cmd/dkim2-dsn-propagator ./cmd/dkim2-dsn-propagator
COPY cmd/dkim2-exim/go.mod cmd/dkim2-exim/go.sum ./cmd/dkim2-exim/
COPY cmd/dkim2ctl ./cmd/dkim2ctl
COPY tools ./tools
COPY vendor ./vendor
COPY contrib/qualification/postfix-milter/cmd/qualify/main.go ./qualification/main.go
RUN CGO_ENABLED=0 go build -trimpath -mod=vendor -o /out/dkim2d ./cmd/dkim2d
RUN CGO_ENABLED=0 go build -trimpath -mod=vendor -o /out/dkim2-milter ./cmd/dkim2-milter
RUN CGO_ENABLED=0 go build -trimpath -mod=vendor -o /out/dkim2-dsn-propagator ./cmd/dkim2-dsn-propagator
RUN CGO_ENABLED=0 go build -trimpath -mod=vendor -o /out/qualify ./qualification/main.go

FROM ${DAEMON_IMAGE} AS daemon
COPY --from=build /out/dkim2d /usr/local/bin/dkim2d
COPY --from=build /out/qualify /usr/local/bin/qualify
USER 2000:2000
ENTRYPOINT ["/usr/local/bin/qualify"]
CMD ["daemon"]

FROM ${POSTFIX_IMAGE} AS stack
COPY --from=build /out/dkim2-milter /usr/local/bin/dkim2-milter
COPY --from=build /out/dkim2-dsn-propagator /usr/local/bin/dkim2-dsn-propagator
COPY --from=build /out/qualify /usr/local/bin/qualify
ENTRYPOINT ["/usr/local/bin/qualify"]
CMD ["stack"]
