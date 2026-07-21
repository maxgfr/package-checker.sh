# Dockerfile - Full version with built-in vulnerability data feeds
# Ships pre-downloaded GHSA and OSV feeds. The set of ecosystems baked in is
# selectable at build time via FEED_ECOSYSTEMS so images stay small:
#   FEED_ECOSYSTEMS=npm   (default) -> only ghsa.purl + osv.purl (identical to
#                                      the historical image content and size)
#   FEED_ECOSYSTEMS=all             -> every ecosystem's ghsa-*/osv-* feeds
#   FEED_ECOSYSTEMS=npm,pypi,golang -> comma list of purl types (npm keeps the
#                                      legacy filenames; others use *-<eco>.purl)
# Any ecosystem not baked in is auto-fetched at runtime from raw GitHub
# (detect-then-load), or you can restrict scanning with --ecosystems.

FROM --platform=$BUILDPLATFORM alpine:3.19 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG FEED_ECOSYSTEMS="npm"

# Prune the full data/ feed set down to the selected ecosystems in the builder
# stage so only the chosen feeds land in the final image.
WORKDIR /build
COPY data/ /build/data/
RUN set -eu; \
    mkdir -p /build/selected; \
    if [ "$FEED_ECOSYSTEMS" = "all" ]; then \
        cp /build/data/*.purl /build/selected/ 2>/dev/null || true; \
    else \
        for eco in $(printf '%s' "$FEED_ECOSYSTEMS" | tr ',' ' '); do \
            if [ "$eco" = "npm" ]; then \
                cp /build/data/ghsa.purl /build/selected/ 2>/dev/null || true; \
                cp /build/data/osv.purl /build/selected/ 2>/dev/null || true; \
            else \
                cp "/build/data/ghsa-$eco.purl" /build/selected/ 2>/dev/null || true; \
                cp "/build/data/osv-$eco.purl" /build/selected/ 2>/dev/null || true; \
            fi; \
        done; \
    fi; \
    echo "FEED_ECOSYSTEMS=$FEED_ECOSYSTEMS -> selected feeds:"; \
    ls -1 /build/selected/ || true

FROM alpine:3.19

ARG VERSION=dev
ARG FEED_ECOSYSTEMS="npm"

# Install only runtime dependencies
RUN apk add --no-cache bash curl gawk

# Create app directory
WORKDIR /app

# Copy the main script
COPY script.sh /app/script.sh

# Copy the pruned vulnerability data feeds from the builder stage
COPY --from=builder /build/selected/ /app/data/

# Make script executable
RUN chmod +x /app/script.sh

# Create symlink for easier access
RUN ln -s /app/script.sh /usr/local/bin/package-checker

# Create workspace directory for user data
WORKDIR /workspace

# Set default command
ENTRYPOINT ["/app/script.sh"]
CMD ["--help"]

# Metadata
LABEL maintainer="package-checker.sh"
LABEL description="Vulnerability checker with built-in package vulnerability feeds (feeds selectable via the FEED_ECOSYSTEMS build-arg; default npm)"
LABEL version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/maxgfr/package-checker.sh"
LABEL org.opencontainers.image.description="Full version with built-in GHSA/OSV package vulnerability feeds (FEED_ECOSYSTEMS build-arg selects ecosystems; default npm)"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.feed-ecosystems="${FEED_ECOSYSTEMS}"
