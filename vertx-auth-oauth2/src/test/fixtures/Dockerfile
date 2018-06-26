FROM jboss/keycloak

ENV KEYCLOAK_USER=user
ENV KEYCLOAK_PASSWORD=password
ENV DB_VENDOR=H2

ADD vertx-test-realm.json /tmp/vertx-test-realm.json

EXPOSE 8080

CMD ["-b", "0.0.0.0", "-Dkeycloak.migration.action=import", "-Dkeycloak.migration.provider=singleFile", "-Dkeycloak.migration.file=/tmp/vertx-test-realm.json", "-Dkeycloak.migration.strategy=OVERWRITE_EXISTING"]

