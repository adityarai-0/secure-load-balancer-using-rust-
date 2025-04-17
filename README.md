# SecureLoadBalancer

A high-reliability, high-security Rust load balancer with HIPAA/ISO compliance features for private cloud environments.

## Overview

SecureLoadBalancer is an advanced HTTP/HTTPS load balancer designed specifically for routing traffic between secure private cloud environments. It includes built-in security features such as honeypot redirection, suspicious traffic detection, and comprehensive audit logging for compliance with healthcare standards.

Key features:

- **Security-first design**: TLS/HTTPS, honeypot diversion, content inspection
- **High reliability**: Circuit breakers, health checks, weighted load balancing
- **Modern performance**: Asynchronous I/O with Tokio, HTTP/2 support
- **Compliance-ready**: Audit logging, tracing headers, metrics collection
- **Real-time monitoring**: Prometheus metrics, structured JSON logging
- **Protected against attacks**: Rate limiting, concurrency controls, timeout protection

## Requirements

- Rust 1.65 or newer
- Linux, macOS, or Windows 

## Dependencies

- `tokio` - Asynchronous runtime
- `hyper` - HTTP/2 implementation
- `hyper-rustls` - TLS support
- `prometheus` - Metrics collection
- `tracing` - Structured logging
- `regex` - Content inspection patterns

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-load-balancer.git
cd secure-load-balancer

# Build in release mode
cargo build --release

# Run the binary
./target/release/secure-load-balancer
```

## Configuration

Configuration is done through environment variables:

```bash
# Core configuration
export LISTEN_ADDR="0.0.0.0:8080"
export METRICS_ADDR="0.0.0.0:9090"
export HONEYPOT_URL="https://honeypot.internal/capture"

# Backend configuration (JSON format)
export BACKENDS='[{"url":"https://private-cloud-a.internal/api","weight":70,"health_endpoint":"/health"},{"url":"https://private-cloud-b.internal/api","weight":30,"health_endpoint":"/ready"}]'

# Performance tuning
export HEALTH_CHECK_INTERVAL_SEC=10
export REQUEST_TIMEOUT_MS=200
export MAX_CONCURRENT_REQUESTS=1000

# Security settings
export RATE_LIMIT_PER_MIN=1000
export CIRCUIT_BREAKER_THRESHOLD=5
export CIRCUIT_BREAKER_RESET_SEC=30
```

## Security Features

### Honeypot Redirection

The load balancer automatically detects suspicious traffic patterns and redirects them to a honeypot endpoint for further analysis. Suspicious patterns include:

- Administrative paths (`/admin`)
- SQL injection attempts
- Path traversal attacks
- XSS attempt signatures

### Circuit Breaker

When backends start failing, the circuit breaker pattern prevents cascading failures:

1. After `CIRCUIT_BREAKER_THRESHOLD` consecutive failures, the backend is temporarily removed from the pool
2. The circuit remains open for `CIRCUIT_BREAKER_RESET_SEC` seconds
3. After the reset period, traffic slowly returns to the backend

### Rate Limiting

Protection against DDoS attacks through IP-based rate limiting:

- Configurable rate limits per client IP
- Automatic expiry of rate limit entries
- Metrics tracking of rate limit events

## Observability

### Prometheus Metrics

Access metrics at `http://{METRICS_ADDR}/metrics`:

- `requests_total{target="backend_url"}` - Request count by backend
- `errors_total{type="error_type"}` - Error count by type
- `request_latency_ms{backend="backend_url"}` - Request latency
- `circuit_state{backend="backend_url"}` - Circuit breaker state

### Structured Logging

JSON-formatted logs include:

- Request IDs for tracing requests through the system
- Client IP addresses for security auditing
- Backend selection and response times
- Circuit breaker state changes
- Health check results

## Compliance Features

### Audit Trail

Every request is logged with:

- Unique request ID
- Timestamp in RFC3339 format
- Client IP address
- Selected backend
- Response status code
- Request latency

### Header Propagation

Security and authentication headers are preserved:

- Authorization headers
- Content type headers
- Cookies for session management
- User agent information

## Performance

The system is designed for high throughput and low latency:

- Asynchronous I/O for handling thousands of concurrent connections
- Weighted load balancing for optimal distribution
- Health-based routing to avoid unhealthy backends
- HTTP/2 support for multiplexing connections

## Docker Support

Build and run with Docker:

```dockerfile
FROM rust:1.65 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
COPY --from=builder /app/target/release/secure-load-balancer /usr/local/bin/
ENTRYPOINT ["secure-load-balancer"]
```

## License

MIT License

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.
