DROP TABLE IF EXISTS cpe;
DROP TABLE IF EXISTS node;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS fix_commit;
DROP TABLE IF EXISTS description;
DROP TABLE IF EXISTS cvss_metrics;
DROP TABLE IF EXISTS cve;

CREATE TABLE cve (
    cve_id VARCHAR(255) PRIMARY KEY,
    euvd_id VARCHAR(255) UNIQUE,
    source_identifier VARCHAR(255),
    vuln_status VARCHAR(255),
    published DATETIME NOT NULL,
    last_modified DATETIME NOT NULL
);

CREATE TABLE cvss_metrics (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    cve_id VARCHAR(255) NOT NULL,
    version VARCHAR(10),
    cvssData JSON,
    exploitabilityScore DECIMAL(3,1),
    impactScore DECIMAL(3,1),
    source VARCHAR(255),
    type VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE
);

CREATE TABLE description (
    description_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    cve_id VARCHAR(255) NOT NULL,
    lang VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE
);

CREATE TABLE fix_commit (
    fix_commit_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    cve_id VARCHAR(255) NOT NULL,
    commit_id VARCHAR(255),
    patch TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE
);

CREATE TABLE reference (
    reference_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    cve_id VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    source TEXT,
    tags JSON,
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE
);

CREATE TABLE node (
    node_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    cve_id VARCHAR(255) NOT NULL,
    operator VARCHAR(50),
    negate BOOLEAN,
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE
);

CREATE TABLE cpe (
    cpe_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    node_id INTEGER NOT NULL,
    vulnerable BOOLEAN NOT NULL,
    criteria VARCHAR(255) NOT NULL,
    matchCriteriaId VARCHAR(36),
    versionStartIncluding VARCHAR(255),
    versionEndIncluding VARCHAR(255),
    FOREIGN KEY (node_id) REFERENCES node(node_id) ON DELETE CASCADE
);