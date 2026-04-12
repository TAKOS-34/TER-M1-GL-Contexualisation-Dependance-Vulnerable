MAVEN_TO_EUVD: dict[tuple, tuple] = {
    ("apache", "log4j-core"):              ("apache", "log4j2"),
    ("apache", "log4j-api"):               ("apache", "log4j2"),
    ("apache", "log4j-slf4j2-impl"):       ("apache", "log4j2"),
    ("org.apache.logging.log4j", "log4j-core"): ("apache", "log4j2"),
    ("org.apache.logging.log4j", "log4j-api"):  ("apache", "log4j2"),
    ("apache", "struts2-core"):            ("apache", "struts"),
    ("org.apache.struts", "struts2-core"): ("apache", "struts"),
    ("org.springframework", "spring-webmvc"):  ("vmware", "spring framework"),
    ("org.springframework", "spring-core"):    ("vmware", "spring framework"),
    ("org.springframework", "spring-beans"):   ("vmware", "spring framework"),
    ("org.springframework", "spring-context"): ("vmware", "spring framework"),
    ("spring-cloud-function-context", "spring-cloud-function-context"): ("vmware", "spring cloud function"),
    ("spring-cloud-gateway-server",   "spring-cloud-gateway-server"):   ("vmware", "spring cloud gateway"),
    ("com.fasterxml.jackson.core", "jackson-databind"):              ("fasterxml", "jackson-databind"),
    ("com.fasterxml.jackson.core", "jackson-annotations"):           ("fasterxml", "jackson-databind"),
    ("com.fasterxml.jackson.dataformat", "jackson-dataformat-yaml"): ("fasterxml", "jackson-databind"),
    ("commons-collections", "commons-collections"): ("apache", "commons collections"),
    ("apache", "commons-collections4"):    ("apache", "commons collections"),
    ("apache", "commons-text"):            ("apache", "commons text"),
    ("apache", "commons-lang3"):           ("apache", "commons lang"),
    ("commons-io", "commons-io"):          ("apache", "commons io"),
    ("org.apache.commons", "commons-text"):         ("apache", "commons text"),
    ("org.apache.commons", "commons-collections4"): ("apache", "commons collections"),
    ("netty-all",    "netty-all"):    ("netty", "netty"),
    ("netty-buffer", "netty-buffer"): ("netty", "netty"),
    ("io.netty",     "netty-all"):    ("netty", "netty"),
    ("io.netty",     "netty-buffer"): ("netty", "netty"),
    ("hibernate-core",  "hibernate-core"): ("red hat", "hibernate orm"),
    ("org.hibernate",   "hibernate-core"): ("red hat", "hibernate orm"),
    ("com.h2database", "h2"):              ("h2database", "h2"),
    ("snakeyaml",  "snakeyaml"):           ("snakeyaml project", "snakeyaml"),
    ("org.yaml",   "snakeyaml"):           ("snakeyaml project", "snakeyaml"),
    ("com.thoughtworks.xstream", "xstream"): ("xstream project", "xstream"),
    ("apache",           "shiro-core"):    ("apache", "shiro"),
    ("org.apache.shiro", "shiro-core"):    ("apache", "shiro"),
    ("com.alibaba", "fastjson"):           ("alibaba", "fastjson"),
    ("com.google.guava", "guava"):         ("google", "guava"),
    ("org.bouncycastle", "bcprov-jdk15on"): ("legion of the bouncy castle", "bouncy castle"),
    ("org.bouncycastle", "bcprov-jdk18on"): ("legion of the bouncy castle", "bouncy castle"),
    ("org.eclipse.jetty", "jetty-server"): ("eclipse", "jetty"),
    ("apache",                  "tomcat-embed-core"): ("apache", "tomcat"),
    ("org.apache.tomcat.embed", "tomcat-embed-core"): ("apache", "tomcat"),
    ("com.fasterxml.woodstox", "woodstox-core"): ("fasterxml", "woodstox"),
}

OSV_PACKAGE_MAP: dict[tuple, str] = {
    ("commons-collections", "commons-collections"): "commons-collections:commons-collections",
    ("apache", "commons-collections4"):             "org.apache.commons:commons-collections4",
    ("apache", "commons-text"):                     "org.apache.commons:commons-text",
    ("apache", "commons-lang3"):                    "org.apache.commons:commons-lang3",
    ("commons-io", "commons-io"):                   "commons-io:commons-io",
    ("snakeyaml",  "snakeyaml"):                    "org.yaml:snakeyaml",
    ("org.yaml",   "snakeyaml"):                    "org.yaml:snakeyaml",
    ("com.h2database", "h2"):                       "com.h2database:h2",
    ("hibernate-core",  "hibernate-core"):          "org.hibernate:hibernate-core",
    ("org.hibernate",   "hibernate-core"):          "org.hibernate:hibernate-core",
    ("com.fasterxml.jackson.core", "jackson-databind"):  "com.fasterxml.jackson.core:jackson-databind",
    ("com.fasterxml.jackson.core", "jackson-annotations"): "com.fasterxml.jackson.core:jackson-annotations",
    ("com.thoughtworks.xstream", "xstream"):        "com.thoughtworks.xstream:xstream",
    ("com.alibaba", "fastjson"):                    "com.alibaba:fastjson",
    ("org.springframework", "spring-webmvc"):       "org.springframework:spring-webmvc",
    ("org.springframework", "spring-core"):         "org.springframework:spring-core",
    ("spring-cloud-function-context", "spring-cloud-function-context"): "org.springframework.cloud:spring-cloud-function-context",
    ("spring-cloud-gateway-server", "spring-cloud-gateway-server"):     "org.springframework.cloud:spring-cloud-gateway-server",
    ("apache", "struts2-core"):                     "org.apache.struts:struts2-core",
    ("org.apache.struts", "struts2-core"):          "org.apache.struts:struts2-core",
    ("netty-all",    "netty-all"):                  "io.netty:netty-all",
    ("netty-buffer", "netty-buffer"):               "io.netty:netty-buffer",
    ("io.netty",     "netty-all"):                  "io.netty:netty-all",
    ("io.netty",     "netty-buffer"):               "io.netty:netty-buffer",
    ("org.bouncycastle", "bcprov-jdk15on"):         "org.bouncycastle:bcprov-jdk15on",
    ("org.bouncycastle", "bcprov-jdk18on"):         "org.bouncycastle:bcprov-jdk18on",
    ("com.google.guava", "guava"):                  "com.google.guava:guava",
    ("org.eclipse.jetty", "jetty-server"):          "org.eclipse.jetty:jetty-server",
    ("apache", "tomcat-embed-core"):                "org.apache.tomcat.embed:tomcat-embed-core",
    ("org.apache.tomcat.embed", "tomcat-embed-core"): "org.apache.tomcat.embed:tomcat-embed-core",
    ("apache", "log4j-core"):                       "org.apache.logging.log4j:log4j-core",
    ("apache", "log4j-api"):                        "org.apache.logging.log4j:log4j-api",
    ("apache", "shiro-core"):                       "org.apache.shiro:shiro-core",
    ("org.apache.shiro", "shiro-core"):             "org.apache.shiro:shiro-core",
    ("com.google.guava", "guava"):                  "com.google.guava:guava",
}


def parse_cpe(cpe: str) -> dict:
    parts = cpe.split(":")
    return {
        "vendor":  parts[3] if len(parts) > 3 else "*",
        "product": parts[4] if len(parts) > 4 else "*",
        "version": parts[5] if len(parts) > 5 else "*",
    }


def resolve_euvd_names(cpe: str) -> list[tuple[str, str]]:
    parsed  = parse_cpe(cpe)
    vendor  = parsed["vendor"]
    product = parsed["product"]

    candidates = []
    key = (vendor, product)
    if key in MAVEN_TO_EUVD:
        candidates.append(MAVEN_TO_EUVD[key])

    short_vendor = vendor.split(".")[-1] if "." in vendor else vendor
    short_key    = (short_vendor, product)
    if short_key in MAVEN_TO_EUVD and short_key != key:
        candidates.append(MAVEN_TO_EUVD[short_key])

    raw_vendor  = short_vendor.replace("-", " ")
    raw_product = product.replace("-", " ").replace("_", " ")
    raw = (raw_vendor, raw_product)
    if raw not in candidates:
        candidates.append(raw)

    short_product = product.split("-")[0]
    if len(short_product) > 4 and short_product != product:
        short = (raw_vendor, short_product)
        if short not in candidates:
            candidates.append(short)

    seen, result = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


def cpe_to_osv_package(cpe: str) -> dict | None:
    parsed  = parse_cpe(cpe)
    vendor  = parsed["vendor"]
    product = parsed["product"]

    key = (vendor, product)
    if key in OSV_PACKAGE_MAP:
        return {"name": OSV_PACKAGE_MAP[key], "ecosystem": "Maven"}

    short_vendor = vendor.split(".")[-1] if "." in vendor else vendor
    short_key    = (short_vendor, product)
    if short_key in OSV_PACKAGE_MAP:
        return {"name": OSV_PACKAGE_MAP[short_key], "ecosystem": "Maven"}

    if "." in vendor:
        return {"name": f"{vendor}:{product}", "ecosystem": "Maven"}

    return None