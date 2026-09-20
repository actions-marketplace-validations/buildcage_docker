# Build buildkit-proxy (statically linked)
#
# BUILDKIT_PROXY_BUILD_TAGS is empty for every real build (including
# published releases): the "testhooks" build tag (see
# docker/explicit/buildkit-proxy/ca_testhooks.go) is compiled in only
# when compose.test-explicit.yaml explicitly passes it, so
# integration-test-only code (a self-signed-cert CA-trust escape hatch) is
# physically absent from the published image's binary.
#
# --platform=$BUILDPLATFORM keeps the Go toolchain on the build host's own
# architecture; GOOS/GOARCH then cross-compile for the target, and
# CGO_ENABLED=0 makes that a plain, fast cross-compile.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS buildkit-proxy-build
ARG BUILDKIT_PROXY_BUILD_TAGS=""
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY docker/explicit/buildkit-proxy/go.mod docker/explicit/buildkit-proxy/go.sum ./
RUN go mod download
COPY docker/explicit/buildkit-proxy/ ./
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -ldflags="-s -w" -tags="${BUILDKIT_PROXY_BUILD_TAGS}" -o /out/buildkit-proxy .

# Bundle the Docker-image scripts (rolldown; see rolldown.scripts.config.js):
# the QuickJS scripts and report-action.node.ts. Architecture-independent
# output, so pinned to --platform=$BUILDPLATFORM like buildkit-proxy-build
# above (no QEMU).
FROM --platform=$BUILDPLATFORM ghcr.io/pnpm/pnpm:11@sha256:e26f380828856f205feaaf42abd157df9ce41bc8e17b662eeaa3379a9638dee0 AS scripts-build
WORKDIR /build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts
COPY rolldown.scripts.config.js ./
COPY src/core/ ./src/core/
COPY docker/explicit/scripts/ ./docker/explicit/scripts/
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm run build:scripts

# Final image
FROM moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3

LABEL org.opencontainers.image.title="buildcage (explicit proxy engine)" \
      org.opencontainers.image.description="Secure Docker build environment using BuildKit's native --proxy-network" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0" \
      org.opencontainers.image.source="https://github.com/buildcage/docker" \
      io.github.buildcage.report-source="true"
# report finds this container by this label; must match src/core/lib/docker/report-source.ts.

# quickjs-ng is the only extra package needed, for source-policy generation.
RUN apk add --no-cache quickjs-ng

COPY --from=buildkit-proxy-build /out/buildkit-proxy /opt/buildcage/bin/buildkit-proxy

RUN mkdir -p /etc/buildkit /var/log/buildkitd
COPY docker/explicit/files/buildkitd.toml /etc/buildkit/buildkitd.toml

# gen-source-policy.js is explicit-only, so it lives next to this Dockerfile
# rather than under src/core/.
COPY --from=scripts-build /build/dist/qjs/docker/explicit/scripts/gen-source-policy.js /opt/buildcage/scripts/gen-source-policy.js

# Never run inside the image: the report action `docker cp`s it out and runs
# it on the runner (see report-action.node.ts).
COPY --from=scripts-build /build/dist/report-action/docker/explicit/scripts/report-action.js /opt/buildcage/scripts/report-action.js

COPY docker/explicit/files/THIRD_PARTY_LICENSES /opt/buildcage/THIRD_PARTY_LICENSES

ENTRYPOINT ["/opt/buildcage/bin/buildkit-proxy"]
