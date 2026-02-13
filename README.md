# Digital Sentinel

AI-powered cybersecurity assessment platform that combines external vulnerability scanning with internal SIEM correlation to provide comprehensive security insights.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Digital Sentinel                              │
│                                                                      │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────────┐  │
│  │   FastAPI     │  │  Wazuh SIEM      │  │  Benchmark Engine     │  │
│  │   REST API    │  │  Correlation     │  │  Industry Analytics   │  │
│  │              │  │  Engine           │  │                       │  │
│  └──────┬───────┘  └────────┬─────────┘  └───────────┬───────────┘  │
│         │                   │                         │              │
│  ┌──────┴───────────────────┴─────────────────────────┴───────────┐  │
│  │                    Service Layer                                │  │
│  └──────┬───────────────────┬─────────────────────────┬───────────┘  │
│         │                   │                         │              │
│  ┌──────┴──────┐  ┌────────┴────────┐  ┌─────────────┴───────────┐  │
│  │ PostgreSQL  │  │     Redis       │  │       Neo4j             │  │
│  │ TimescaleDB │  │   Cache/Queue   │  │   Graph Relationships   │  │
│  └─────────────┘  └─────────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Setup

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for databases)
- Git

### Local Development

```bash
# Clone the repository
git clone <repo-url> && cd digital-sentinel

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Copy environment configuration
cp .env.example .env
# Edit .env with your settings

# Start databases
docker compose up -d postgres redis neo4j

# Run database migrations
alembic upgrade head

# Start the development server
uvicorn src.app:app --reload --host 0.0.0.0 --port 8000
```

### Docker Deployment

```bash
# Build and start all services
docker compose up -d --build

# Check service health
curl http://localhost:8000/health
```

### Coolify Deployment

This project is Coolify-compatible. Configure using:

- **Build Pack**: Dockerfile
- **Port**: 8000
- **Health Check**: `/health/live`
- **Environment Variables**: See `.env.example`

## API Documentation

### Health Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Full health check with service status |
| `/health/ready` | GET | Readiness probe (dependency check) |
| `/health/live` | GET | Liveness probe (process alive) |

### Wazuh Cross-Domain Correlation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/wazuh/connect` | POST | Configure Wazuh SIEM connection |
| `/api/wazuh/correlate/{org}` | POST | Run cross-domain correlation |
| `/api/wazuh/timeline/{org}` | GET | Unified threat timeline |
| `/api/wazuh/alerts/{org}` | GET | Recent Wazuh alerts (translated) |

### Industry Benchmark Engine

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/benchmarks/{org}` | GET | Organisation's benchmark position |
| `/api/benchmarks/industry/{sector}` | GET | Industry sector statistics |
| `/api/benchmarks/trends/{sector}` | GET | Industry trend data over time |
| `/api/benchmarks/compare/{org}` | POST | Comparative analysis |

### Interactive API Docs

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_ENVIRONMENT` | `development` | Environment (development/staging/production) |
| `SENTINEL_DEBUG` | `false` | Enable debug mode |
| `SENTINEL_LOG_LEVEL` | `INFO` | Logging level |
| `SENTINEL_LOG_FORMAT` | `json` | Log format (json/console) |
| `SENTINEL_DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL connection string |
| `SENTINEL_REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `SENTINEL_NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `SENTINEL_SECRET_KEY` | *(placeholder)* | JWT signing key — **change in production** |
| `SENTINEL_ALLOWED_ORIGINS` | `http://localhost:3000` | CORS allowed origins (comma-separated) |
| `SENTINEL_RATE_LIMIT_DEFAULT` | `100/minute` | Default rate limit |
| `SENTINEL_WAZUH_API_URL` | *(empty)* | Wazuh API endpoint |
| `SENTINEL_WAZUH_API_USER` | *(empty)* | Wazuh API username |
| `SENTINEL_WAZUH_API_PASSWORD` | *(empty)* | Wazuh API password |

See `.env.example` for the complete list.

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run beast tests only
pytest -m beast

# Run a specific milestone's tests
pytest tests/test_milestone21_wazuh_beast.py
pytest tests/test_milestone22_benchmark_beast.py
pytest tests/test_milestone23_production_beast.py
```

## Deployment Checklist

- [ ] Update `SENTINEL_SECRET_KEY` to a strong random value
- [ ] Set `SENTINEL_ENVIRONMENT=production`
- [ ] Set `SENTINEL_DEBUG=false`
- [ ] Configure `SENTINEL_ALLOWED_ORIGINS` for your domains
- [ ] Set up PostgreSQL with TimescaleDB extension
- [ ] Configure Redis for caching and rate limiting
- [ ] Set up Neo4j for graph relationships
- [ ] Configure Wazuh API credentials if using SIEM integration
- [ ] Set appropriate rate limits for your expected traffic
- [ ] Enable HTTPS via reverse proxy (nginx/Caddy)
- [ ] Set `SENTINEL_LOG_FORMAT=json` for log aggregation
- [ ] Run database migrations: `alembic upgrade head`
- [ ] Verify health checks: `curl /health`

## Licence

Proprietary — Digital Sentinel Platform.
