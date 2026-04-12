"""Configuration management with environment validation."""
import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from functools import lru_cache

# Load .env file on import
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)
except ImportError:
    pass  # python-dotenv not installed


@dataclass
class DatabaseConfig:
    """Database configuration."""
    url: str = field(default_factory=lambda: os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://root:password@localhost:3306/cve_database"
    ))
    echo: bool = field(default_factory=lambda: os.getenv("DB_ECHO", "false").lower() == "true")
    pool_size: int = field(default_factory=lambda: int(os.getenv("DB_POOL_SIZE", "10")))
    max_overflow: int = field(default_factory=lambda: int(os.getenv("DB_MAX_OVERFLOW", "20")))


@dataclass
class SourcesConfig:
    """Vulnerability sources configuration."""
    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    osv_api_base: str = "https://api.osv.dev/v1/query"
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    github_api_url: str = "https://api.github.com/graphql"
    jvn_api_base: str = "https://jvndb.jvn.jp/myjvn"
    
    # API Keys from environment
    nvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))
    euvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("EUVD_API_KEY"))
    
    # Request configuration
    timeout: float = field(default_factory=lambda: float(os.getenv("HTTP_TIMEOUT", "30.0")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("HTTP_MAX_RETRIES", "3")))
    retry_backoff: float = field(default_factory=lambda: float(os.getenv("HTTP_RETRY_BACKOFF", "0.5")))


@dataclass
class AIConfig:
    """AI fallback configuration."""
    enabled: bool = field(default_factory=lambda: os.getenv("AI_FALLBACK_ENABLED", "false").lower() == "true")
    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_HOST_URL", "http://localhost:11434"))
    model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "mistral:7b-instruct-v0.2-q4_0"))
    timeout: float = field(default_factory=lambda: float(os.getenv("AI_TIMEOUT", "60.0")))


@dataclass
class SourcesConfig:
    """Vulnerability sources configuration."""
    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    osv_api_base: str = "https://api.osv.dev/v1/query"
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    github_api_url: str = "https://api.github.com/graphql"
    jvn_api_base: str = "https://jvndb.jvn.jp/myjvn"
    
    # API Keys from environment
    nvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))
    euvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("EUVD_API_KEY"))
    
    # Request configuration
    timeout: float = field(default_factory=lambda: float(os.getenv("HTTP_TIMEOUT", "30.0")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("HTTP_MAX_RETRIES", "3")))
    retry_backoff: float = field(default_factory=lambda: float(os.getenv("HTTP_RETRY_BACKOFF", "0.5")))


@dataclass
class AppConfig:
    """Application configuration."""
    title: str = "Pradeo Vulnerability Aggregator"
    version: str = "2.0.0"
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    workers: int = field(default_factory=lambda: int(os.getenv("WORKERS", "4")))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))


class Settings:
    """Main settings container."""
    
    def __init__(self):
        self.database = DatabaseConfig()
        self.sources = SourcesConfig()
        self.ai = AIConfig()
        self.app = AppConfig()
        self.base_dir = Path(__file__).parent.parent
    
    def validate(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        if not self.database.url:
            issues.append("DATABASE_URL not configured")
        
        if self.sources.max_retries < 0:
            issues.append("HTTP_MAX_RETRIES must be >= 0")
        
        if self.sources.timeout <= 0:
            issues.append("HTTP_TIMEOUT must be > 0")
        
        return issues
    
    def __repr__(self) -> str:
        return (
            f"Settings(db={self.database.url[:50]}..., "
            f"debug={self.app.debug}, log_level={self.app.log_level})"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get singleton settings instance."""
    settings = Settings()
    issues = settings.validate()
    if issues:
        print(f"⚠️  Configuration warnings: {issues}")
    return settings


# Export singleton instance
settings = get_settings()


# Backward compatibility: export source URLs as module constants
EUVD_BASE = settings.sources.euvd_base_url
EUVD_CSV_DUMP = f"{EUVD_BASE}/dump/cve-euvd-mapping"
EUVD_SEARCH = f"{EUVD_BASE}/search"
EUVD_BY_ID = f"{EUVD_BASE}/enisaid"
EUVD_LAST = f"{EUVD_BASE}/lastvulnerabilities"
EUVD_EXPLOITED = f"{EUVD_BASE}/exploitedvulnerabilities"
EUVD_CRITICAL = f"{EUVD_BASE}/criticalvulnerabilities"

OSV_API_BASE = settings.sources.osv_api_base
NVD_API_BASE = settings.sources.nvd_api_base
NVD_API_KEY = settings.sources.nvd_api_key
GITHUB_ADVISORY_URL = settings.sources.github_api_url
GITHUB_TOKEN = settings.sources.github_token
JVN_API_BASE = settings.sources.jvn_api_base


# HTTP client factory
import httpx


def make_client() -> httpx.AsyncClient:
    """Create configured async HTTP client."""
    return httpx.AsyncClient(
        follow_redirects=True,
        timeout=settings.sources.timeout,
        limits=httpx.Limits(
            max_connections=20,
            max_keepalive_connections=10,
        ),
    )
