FROM python:3.11-slim

LABEL maintainer="TreexHD"
LABEL description="SNI Proxy — TLS SNI-based transparent proxy with port-knocking whitelist"

WORKDIR /app

# Copy application
COPY sniproxy.py .
RUN mkdir -p data

# Environment variables
ENV PYTHONUNBUFFERED=1

# Expose default ports
EXPOSE 443 9999

# Default command
CMD ["python", "sniproxy.py", "config.json"]
