
### Architecture Overview

```
├── core/                          # Shared infrastructure
│   ├── config.py                 # Configuration management
│   ├── exceptions.py             # Exception hierarchy
│   ├── logger.py                 # Logging setup
│   └── types.py                  # Type definitions
│
├── models/                        # Database & Serialization
│   ├── database.py               # SQLAlchemy ORM models
│   ├── schemas.py                # Pydantic request/response models
│
├── sources/                       # Vulnerability Source Adapters
│   ├── base.py                   # Abstract base class + mixins
│   ├── euvd.py                   # EUVD source
│   ├── osv.py                    # OSV source
│   ├── nvd.py                    # NVD source
│   ├── github.py                 # GitHub Advisory source (stub)
│   └── jvn.py                    # JVN source (stub)
│
├── services/                      # Business Logic Layer
│   ├── aggregator.py             # Core aggregation orchestrator
│   ├── vulnerability_service.py   # CVE query/search service
│  
│   
│
├── matching/                      # CPE & Version Matching
│   ├── cpe.py                    # CPE parsing & normalization
│   ├── version.py                # Version comparison logic
│   └── normalizer.py             # Data normalization (planned)
│
├── routers/                       # FastAPI Route Handlers
│   ├── health.py                 # Health check endpoints
│   ├── query.py                  # CPE query endpoints
│   ├── sync.py                   # Sync & status endpoints
│   └── debug.py                  # Debug endpoints
│
├── utils/                         # Utility Functions
│   ├── http.py                   # HTTP utilities with retry logic
│   └── validators.py             # Validation functions
│
├── main.py                        # FastAPI application entry point
├── aggregator.py                  # Backward compatibility wrapper
└── requirements.txt              # Dependencies
```


### Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env with your settings

# 3. Initialize database
python -c "from models import init_db; init_db()"

# 4. Run server
uvicorn main:app --reload
```

### API Endpoints

#### Health & Status
- `GET /` - Service status
- `GET /health` - Sources health check
- `GET /sync/status` - Database sync status

#### Query Vulnerabilities
- `POST /query` - Query single CPE
- `POST /query/bulk` - Query multiple CPEs
- `GET /cve/{cve_id}` - Get CVE details
- `GET /cve/search?q=...` - Search CVEs
- `GET /cve/latest` - Latest CVEs

#### Management
- `POST /sync/force` - Force sync

#### Debug (development only)
- `GET /debug/sources` - List sources
- `GET /debug/config` - Show config

### 🔌 Vulnerability Sources

#### EUVD (Primary)
- European vulnerability database
- Richest data source
- Caching & rate limiting enabled
- Priority: 1

#### OSV (Fallback)
- Open Source Vulnerabilities
- Good for open source packages
- Priority: 2

#### NVD (Index)
- National Vulnerability Database
- Used as CVE ID index only
- Data enriched from EUVD/OSV
- Priority: 3

### Configuration

Copy `.env.example` to `.env` and configure:

```ini
# Database
DATABASE_URL=mysql+pymysql://user:password@host/db

# API Keys
NVD_API_KEY=your_key
GITHUB_TOKEN=your_token

# Runtime
DEBUG=true
LOG_LEVEL=INFO
HTTP_TIMEOUT=30.0
```

### Testing

```bash
# Run tests
pytest -v

# Coverage report
pytest --cov=src/backend

# Type checking
mypy src/backend

# Code style
black src/backend
flake8 src/backend
```

### Data Flow

```
Client CPE Query
    ↓
POST /query endpoint
    ↓
Aggregator.fetch_and_sync()
    ├→ EUVD Source (check cache → query)
    │   ├→ If found & vulnerable → write to DB ✓
    │   ├→ If found & not vulnerable → stop (definitive)
    │   └→ If not found → continue to next
    │
    ├→ OSV Source (same pattern)
    │
    └→ NVD Source (ID index only, enrich later)
    
    ↓
Write normalized data to DB
    ├→ CveItem (main CVE record)
    ├→ CvssMetric (CVSS scoring)
    ├→ Description (vulnerability description)
    ├→ Reference (external URLs)
    └→ CpeMatch (affected products)
    
    ↓
Return results to client
    ├→ CVE ID list
    ├→ Base scores
    └→ Status information
```

### Source Chain Logic

1. **Query all sources in priority order**
2. **For each source:**
   - If vulnerabilities found AND version affected → write to DB + stop
   - If vulnerabilities found BUT version not affected → stop (definitive answer)
   - If no vulnerabilities found → try next source

3. **If no source had data:**
   - Store "unknown" marker to avoid re-querying

4. **Concurrent bulk queries** with `fetch_bulk()`

### 🛠️ Development

#### Adding a New Source

```python
# In sources/newsource.py
from sources.base import VulnerabilitySource
from core.logger import get_logger

logger = get_logger(__name__)

class NewSource(VulnerabilitySource):
    @property
    def name(self) -> str:
        return "NEW_SOURCE"
    
    async def healthy(self) -> bool:
        # Quick health check
        pass
    
    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        # Implement query logic
        pass
```

Then add to `aggregator.py` sources list:
```python
self._sources = [
    EUVDSource(),
    OSVSource(),
    NVDSource(),
    NewSource(),  # ← Add here
]
```

#### Adding a New API Endpoint

```python
# In main.py
@app.get("/new-endpoint", tags=["Feature"])
async def new_endpoint(db: Session = Depends(get_db)):
    """Endpoint description."""
    # Implementation
    return result
```

### Database Schema

See `models/database.py` for ORM models:
- **CveItem** - Main CVE record
- **CvssMetric** - CVSS scoring data
- **Description** - Multi-language descriptions
- **Reference** - External links
- **Node** - CPE configuration node
- **CpeMatch** - Affected CPE criteria
- **FixCommit** - Patch/fix commits

### Security Notes

- Sensitive values (API keys) in environment variables
- No credentials in logs
- SQL injection prevented by SQLAlchemy ORM
- Rate limiting per source
- Request timeouts configured


### Logging

All activity logged to:
- **Console** - INFO and above
- **`logs/aggregator.log`** - DEBUG and above
- **`logs/error.log`** - ERROR and above

Logs include source, function, line number, and timestamp.


### Contributing

Pull requests welcome! Please:
1. Follow the architecture pattern
2. Add type hints
3. Include logging
4. Add tests
5. Update documentation
