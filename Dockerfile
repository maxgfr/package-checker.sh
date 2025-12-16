# Dockerfile - Full version with vulnerability data feeds
# This image includes pre-downloaded GHSA and OSV vulnerability feeds
# Image size: ~14MB (includes ~13MB of vulnerability data)

FROM alpine:latest

ARG VERSION=dev

# Install required dependencies
# Use --no-scripts to avoid post-install script issues with QEMU emulation
RUN apk add --no-cache --no-scripts bash curl gawk && \
  # Manually set up bash as the default shell for this image
  sed -i 's|/bin/ash|/bin/bash|g' /etc/passwd 2>/dev/null || true

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
