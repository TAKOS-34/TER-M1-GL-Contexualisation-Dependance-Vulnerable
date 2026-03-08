INSERT INTO cve (cve_id, source_identifier, vuln_status, published, last_modified)
VALUES ('CVE-2021-44228', 'nvd@nist.gov', 'Analyzed', '2021-12-10 03:15:00', '2021-12-10 03:15:00');

INSERT INTO description (lang, value, cve_id)
VALUES ('en', 'Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features...', 'CVE-2021-44228');

INSERT INTO cvss_v3 (attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, base_score, source, type, cve_id)
VALUES (
    'NETWORK', 'LOW', 'NONE', 'NONE', 'CHANGED', 'HIGH', 'HIGH', 'HIGH', 10.0,
    'nvd@nist.gov', 'Primary', 'CVE-2021-44228'
);

INSERT INTO node (operator, negate, cve_id) 
VALUES ('OR', 0, 'CVE-2021-44228');

INSERT INTO cpe (vulnerable, criteria, node_id)
VALUES 
('1', 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', 1),
('1', 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', 1);