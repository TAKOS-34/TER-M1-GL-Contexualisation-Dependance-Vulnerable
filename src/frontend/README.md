# Installer les dépendances

`mvn clean compile`

# Curl Syft

`curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .`

# Lancer le logiciel

`mvn exec:java`