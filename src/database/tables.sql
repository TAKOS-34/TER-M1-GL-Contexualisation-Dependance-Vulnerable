DROP TABLE IF EXISTS cpe;
DROP TABLE IF EXISTS node;
DROP TABLE IF EXISTS reference;
DROP TABLE IF EXISTS fix_commit;
DROP TABLE IF EXISTS description;
DROP TABLE IF EXISTS cvss_v3;
DROP TABLE IF EXISTS cve;

CREATE TABLE cve (
    cve_id VARCHAR(255) PRIMARY KEY,
    source_identifier VARCHAR(255),
    vuln_status VARCHAR(100),
    published DATETIME,
    last_modified DATETIME
);

CREATE TABLE cvss_v3 (
    cvss_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    vector_string VARCHAR(255),
    attack_vector VARCHAR(100),
    attack_complexity VARCHAR(100),
    privileges_required VARCHAR(100),
    user_interaction VARCHAR(100),
    scope VARCHAR(100),
    confidentiality_impact VARCHAR(100),
    integrity_impact VARCHAR(100),
    availability_impact VARCHAR(100),
    base_score DECIMAL(3,1),
    base_severity VARCHAR(100),
    source VARCHAR(255),
    type VARCHAR(100),
    cve_id VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
);

CREATE TABLE description (
    description_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    lang VARCHAR(50),
    value TEXT,
    cve_id VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
);

CREATE TABLE fix_commit (
    fix_commit_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    patch LONGTEXT,
    cve_id VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
);

CREATE TABLE reference (
    reference_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    url VARCHAR(255),
    source TEXT,
    tags JSON,
    cve_id VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
);

CREATE TABLE node (
    node_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    operator VARCHAR(50),
    negate BOOLEAN,
    cve_id VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id)
);

CREATE TABLE cpe (
    cpe_id INTEGER PRIMARY KEY AUTO_INCREMENT,
    vulnerable VARCHAR(100),
    criteria VARCHAR(255),
    node_id INTEGER,
    FOREIGN KEY (node_id) REFERENCES node(node_id)
);