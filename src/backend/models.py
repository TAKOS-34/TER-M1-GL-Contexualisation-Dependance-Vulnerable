import os
from dotenv import load_dotenv
from typing import List, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, JSON, DECIMAL, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:password@localhost:3306/cve_database")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Session: # type: ignore
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class CveItem(Base):
    __tablename__ = "cve"
    cve_id = Column(String(255), primary_key=True)
    euvd_id = Column(String(255), nullable=True, index=True)
    sourceIdentifier = Column("source_identifier", String(255))
    vulnStatus = Column("vuln_status", String(255))
    published = Column(DateTime, nullable=False)
    lastModified = Column("last_modified", DateTime, nullable=False)
    
    # Relations mises à jour
    descriptions = relationship("Description", back_populates="cve_item", cascade="all, delete-orphan")
    references = relationship("Reference", back_populates="cve_item", cascade="all, delete-orphan")
    # Changement de nom ici pour être générique
    cvss_metrics = relationship("CvssMetric", back_populates="cve_item", cascade="all, delete-orphan")
    nodes = relationship("Node", back_populates="cve_item", cascade="all, delete-orphan")
    fix_commits = relationship("FixCommit", back_populates="cve_item", cascade="all, delete-orphan")

class Description(Base):
    __tablename__ = "description"
    id = Column("description_id", Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE"))
    lang = Column(String(50), nullable=False)
    value = Column(Text, nullable=False)
    cve_item = relationship("CveItem", back_populates="descriptions")

class Reference(Base):
    __tablename__ = "reference"
    id = Column("reference_id", Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE"))
    url = Column(String(500), nullable=False)
    source = Column(Text)
    tags = Column(JSON)
    cve_item = relationship("CveItem", back_populates="references")

class CvssMetric(Base): # Ancien CvssV30 renommé et amélioré
    __tablename__ = "cvss_metrics"
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE"))
    version = Column(String(10)) # "3.0", "3.1" ou "4.0"
    cvssData = Column(JSON) # Contient le vecteur et le score base
    exploitabilityScore = Column(DECIMAL(3, 1))
    impactScore = Column(DECIMAL(3, 1))
    source = Column(String(255))
    type = Column(String(255)) # Primary ou Secondary
    cve_item = relationship("CveItem", back_populates="cvss_metrics")

class Node(Base):
    __tablename__ = "node"
    id = Column("node_id", Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey("cve.cve_id", ondelete="CASCADE")) # Lien direct vers CVE
    operator = Column(String(50))
    negate = Column(Boolean)
    cve_item = relationship("CveItem", back_populates="nodes")
    cpe_matches = relationship("CpeMatch", back_populates="node", cascade="all, delete-orphan")

class CpeMatch(Base):
    __tablename__ = "cpe"
    id = Column("cpe_id", Integer, primary_key=True, autoincrement=True)
    node_id = Column(Integer, ForeignKey("node.node_id", ondelete="CASCADE"))
    vulnerable = Column(Boolean, nullable=False)
    criteria = Column(String(255), nullable=False)
    matchCriteriaId = Column(String(36))
    versionStartIncluding = Column(String(255))
    versionEndIncluding = Column(String(255))
    node = relationship("Node", back_populates="cpe_matches")

class FixCommit(Base):
    __tablename__ = 'fix_commit'
    id = Column("fix_commit_id", Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(255), ForeignKey('cve.cve_id', ondelete='CASCADE'))
    commit_id = Column(String(255))
    patch = Column(Text, nullable=False)
    cve_item = relationship("CveItem", back_populates="fix_commits")

