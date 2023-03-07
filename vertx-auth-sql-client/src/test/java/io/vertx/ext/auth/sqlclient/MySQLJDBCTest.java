package io.vertx.ext.auth.sqlclient;

import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.jdbcclient.JDBCConnectOptions;
import io.vertx.jdbcclient.JDBCPool;
import io.vertx.sqlclient.PoolOptions;
import org.junit.*;
import org.junit.runner.RunWith;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;

@RunWith(VertxUnitRunner.class)
public class MySQLJDBCTest {

  @ClassRule
  public static final GenericContainer<?> container = new GenericContainer<>("mysql:5.7")
    .withEnv("MYSQL_USER", "mysql")
    .withEnv("MYSQL_PASSWORD", "password")
    .withEnv("MYSQL_ROOT_PASSWORD", "password")
    .withEnv("MYSQL_DATABASE", "testschema")
    .withExposedPorts(3306)
    .withClasspathResourceMapping("mysql-auth-ddl-test.sql", "/docker-entrypoint-initdb.d/init.sql", BindMode.READ_ONLY);

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private JDBCPool mysql;

  @Before
  public void before() {
    // Create the client pool
    mysql = JDBCPool.pool(
      rule.vertx(),
      // default config
      new JDBCConnectOptions()
        .setJdbcUrl("jdbc:mysql://" + container.getHost() + ":" + container.getMappedPort(3306) + "/testschema?useSSL=false&serverTimezone=UTC&useLegacyDatetimeCode=false")
        .setUser("mysql")
        .setPassword("password"),
      // default pool config
      new PoolOptions()
        .setMaxSize(5));
  }

  @After
  public void after() {
    mysql.close();
  }

  @Test
  public void testAuthenticate(TestContext should) {
    final Async test = should.async();

    AuthenticationProvider authn = SqlAuthentication.create(mysql);

    Credentials authInfo = new UsernamePasswordCredentials("lopus", "secret");

    authn.authenticate(authInfo)
      .onComplete(authenticate -> {
        should.assertTrue(authenticate.succeeded());
        should.assertNotNull(authenticate.result());
        should.assertEquals("lopus", authenticate.result().principal().getString("username"));
        test.complete();
      });
  }

  @Test
  public void testAuthenticateBadPassword(TestContext should) {
    final Async test = should.async();

    AuthenticationProvider authn = SqlAuthentication.create(mysql);

    Credentials authInfo = new UsernamePasswordCredentials("lopus", "s3cr3t");

    authn.authenticate(authInfo)
      .onComplete(authenticate -> {
        should.assertTrue(authenticate.failed());
        should.assertNull(authenticate.result());
        should.assertEquals("Invalid username/password", authenticate.cause().getMessage());
        test.complete();
      });
  }

  @Test
  public void testAuthenticateBadUser(TestContext should) {
    final Async test = should.async();

    AuthenticationProvider authn = SqlAuthentication.create(mysql);

    Credentials authInfo = new UsernamePasswordCredentials("lopes", "s3cr3t");

    authn.authenticate(authInfo)
      .onComplete(authenticate -> {
        should.assertTrue(authenticate.failed());
        should.assertNull(authenticate.result());
        should.assertEquals("Invalid username/password", authenticate.cause().getMessage());
        test.complete();
      });
  }

  @Test
  public void testAuthoriseHasRole(TestContext should) {
    final Async test = should.async();

    Credentials authInfo = new UsernamePasswordCredentials("lopus", "secret");

    AuthenticationProvider authn = SqlAuthentication.create(mysql);

    authn.authenticate(authInfo)
      .onComplete(authenticate -> {
        should.assertTrue(authenticate.succeeded());
        final User user = authenticate.result();
        should.assertNotNull(user);
        AuthorizationProvider authz = SqlAuthorization.create(mysql);
        authz.getAuthorizations(user)
          .onComplete(getAuthorizations -> {
            should.assertTrue(getAuthorizations.succeeded());
            // attest
            should.assertTrue(RoleBasedAuthorization.create("dev").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseNotHasRole(TestContext should) {
    final Async test = should.async();

    Credentials authInfo = new UsernamePasswordCredentials("lopus", "secret");

    AuthenticationProvider authn = SqlAuthentication.create(mysql);

    authn.authenticate(authInfo)
      .onComplete(authenticate -> {
        should.assertTrue(authenticate.succeeded());
        final User user = authenticate.result();
        should.assertNotNull(user);
        AuthorizationProvider authz = SqlAuthorization.create(mysql);
        authz.getAuthorizations(user)
          .onComplete(getAuthorizations -> {
            should.assertTrue(getAuthorizations.succeeded());
            // attest
            should.assertFalse(RoleBasedAuthorization.create("manager").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseHasPermission(TestContext should) {
    final Async test = should.async();

    Credentials authInfo = new UsernamePasswordCredentials("lopus", "secret");

    AuthenticationProvider authn = SqlAuthentication.create(mysql);

    authn.authenticate(authInfo)
      .onComplete(authenticate -> {
        should.assertTrue(authenticate.succeeded());
        final User user = authenticate.result();
        should.assertNotNull(user);
        AuthorizationProvider authz = SqlAuthorization.create(mysql);
        authz.getAuthorizations(user)
          .onComplete(getAuthorizations -> {
            should.assertTrue(getAuthorizations.succeeded());
            // attest
            should.assertTrue(PermissionBasedAuthorization.create("commit_code").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseNotHasPermission(TestContext should) {
    final Async test = should.async();

    Credentials authInfo = new UsernamePasswordCredentials("lopus", "secret");

    AuthenticationProvider authn = SqlAuthentication.create(mysql);

    authn.authenticate(authInfo)
      .onComplete(authenticate -> {
        should.assertTrue(authenticate.succeeded());
        final User user = authenticate.result();
        should.assertNotNull(user);
        AuthorizationProvider authz = SqlAuthorization.create(mysql);
        authz.getAuthorizations(user)
          .onComplete(getAuthorizations -> {
            should.assertTrue(getAuthorizations.succeeded());
            // attest
            should.assertFalse(PermissionBasedAuthorization.create("eat_sandwich").match(user));
            test.complete();
          });
      });
  }
}
