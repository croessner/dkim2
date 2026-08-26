ARG BUILD_IMAGE=golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6
ARG DAEMON_IMAGE=debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e
ARG POSTFIX_IMAGE=chrroessner/postfix@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c

FROM ${BUILD_IMAGE} AS build
WORKDIR /source
COPY go.work go.work.sum ./
COPY lib ./lib
COPY cmd/dkim2d ./cmd/dkim2d
COPY cmd/dkim2-milter ./cmd/dkim2-milter
COPY cmd/dkim2-exim/go.mod cmd/dkim2-exim/go.sum ./cmd/dkim2-exim/
COPY cmd/dkim2ctl ./cmd/dkim2ctl
COPY tools ./tools
COPY vendor ./vendor
COPY contrib/qualification/postfix-milter/cmd/qualify/main.go ./qualification/main.go
RUN CGO_ENABLED=0 go build -trimpath -mod=vendor -o /out/dkim2d ./cmd/dkim2d
RUN CGO_ENABLED=0 go build -trimpath -mod=vendor -o /out/dkim2-milter ./cmd/dkim2-milter
RUN CGO_ENABLED=0 go build -trimpath -mod=vendor -o /out/qualify ./qualification/main.go

FROM ${DAEMON_IMAGE} AS daemon
COPY --from=build /out/dkim2d /usr/local/bin/dkim2d
COPY --from=build /out/qualify /usr/local/bin/qualify
USER 2000:2000
ENTRYPOINT ["/usr/local/bin/qualify"]
CMD ["daemon"]

FROM ${POSTFIX_IMAGE} AS stack
COPY --from=build /out/dkim2-milter /usr/local/bin/dkim2-milter
COPY --from=build /out/qualify /usr/local/bin/qualify
ENTRYPOINT ["/usr/local/bin/qualify"]
CMD ["stack"]
