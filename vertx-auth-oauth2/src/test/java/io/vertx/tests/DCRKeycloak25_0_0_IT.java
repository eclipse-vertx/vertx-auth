package io.vertx.tests;

import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunnerWithParametersFactory;
import java.util.Arrays;
import java.util.List;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

@RunWith(Parameterized.class)
@Parameterized.UseParametersRunnerFactory(VertxUnitRunnerWithParametersFactory.class)
public class DCRKeycloak25_0_0_IT {

  @ClassRule
  public static final GenericContainer<?> container = new GenericContainer<>("quay.io/keycloak/keycloak:25.0.0")
    .withEnv("KEYCLOAK_USER", "admin")
    .withEnv("KEYCLOAK_PASSWORD", "secret")
    .withEnv("DB_VENDOR", "H2")
    .withExposedPorts(8080, 8443)
    .withClasspathResourceMapping("vertx-it-dcr-realm.json", "/tmp/fixtures.json", BindMode.READ_ONLY)
    .withCommand("-b", "0.0.0.0", "-Dkeycloak.migration.action=import", "-Dkeycloak.migration.provider=singleFile", "-Dkeycloak.migration.file=/tmp/fixtures.json", "-Dkeycloak.migration.strategy=OVERWRITE_EXISTING")
    .waitingFor(Wait.forLogMessage(".*Keycloak.*started.*", 1));


  @Parameterized.Parameters
  public static List<String> sites() {
    return Arrays.asList("http", "https");
  }

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private final String proto;
  private String site;

  public DCRKeycloak25_0_0_IT(String proto) {
    this.proto = proto;
  }

  @Before
  public void setUp() {
    switch (proto) {
      case "http":
        site = proto + "://" + container.getHost() + ":" + container.getMappedPort(8080);
        break;
      case "https":
        site = proto + "://" + container.getHost() + ":" + container.getMappedPort(8443);
        break;
      default:
        throw new IllegalArgumentException("Invalid proto: " + proto);
    }
  }

  @Test
  public void test(TestContext should) {
    final Async test = should.async();

  }
}
