# Dockerfile - Full version with vulnerability data feeds
# This image includes pre-downloaded GHSA and OSV vulnerability feeds
# Image size: ~14MB (includes ~13MB of vulnerability data)

FROM --platform=$BUILDPLATFORM alpine:3.19 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install required dependencies
RUN apk add --no-cache bash curl gawk

FROM alpine:3.19

ARG VERSION=dev

# Install only runtime dependencies
RUN apk add --no-cache bash curl gawk

# Create app directory
WORKDIR /app

# Copy the main script
COPY script.sh /app/script.sh

# Copy vulnerability data feeds
COPY data/ /app/data/

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
LABEL description="Vulnerability checker for npm packages with built-in GHSA and OSV feeds"
LABEL version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/maxgfr/package-checker.sh"
LABEL org.opencontainers.image.description="Full version with vulnerability data feeds (~14MB)"
LABEL org.opencontainers.image.licenses="MIT"
