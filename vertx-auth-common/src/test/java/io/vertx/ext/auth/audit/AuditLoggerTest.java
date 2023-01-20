package io.vertx.ext.auth.audit;

import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;

@RunWith(VertxUnitRunner.class)
public class AuditLoggerTest {

  static {
    AuditLogger
      .init(
        new JWK(
          new JsonObject()
            .put("kty", "oct")
            .put("alg", "HS256")
            .put("k", "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ")));
  }

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testSync(TestContext should) throws IOException {

    AuditLogger log = AuditLogger.instance();

    log.succeeded(Marker.SECURITY, new StructuredData().setSub("paulo"));
    log.succeeded(Marker.EVENT, new StructuredData().setSub("paulo"));
    log.succeeded(Marker.AUDIT, new StructuredData().setSub("paulo"));

    // 2023-01-20T16:33:50.052877059+01:00[Europe/Amsterdam] [iat=1674228830051 sub="paulo"]; sig=zN0nPVo++KrXqW/qF1p8aDaVxtLbEQEpKScfuFFvq18=
    // 2023-01-20T16:33:50.066322140+01:00[Europe/Amsterdam] [iat=1674228830066 sub="paulo"]
    // 2023-01-20T16:33:50.066610521+01:00[Europe/Amsterdam] [iat=1674228830066 sub="*****"]; sig=pif5e4QepkQbJAcgkLbsV9fTjMxlo8yC8yzpdeW5id0=

    log.succeeded(Marker.SECURITY, new StructuredData(new UsernamePasswordCredentials("pmlopes@gmail.com", "password")));
    log.succeeded(Marker.EVENT, new StructuredData(new UsernamePasswordCredentials("pmlopes@gmail.com", "password")));
    log.succeeded(Marker.AUDIT, new StructuredData(new UsernamePasswordCredentials("pmlopes@gmail.com", "password")));

    // 2023-01-20T16:36:03.674704725+01:00[Europe/Amsterdam] [iat=1674228963674 password="********" username="pmlopes@gmail.com"]; sig=q3RYnRQVkMEDpn3fTiii+6uDL+KsjiG4ISKBYxMdlEo=
    // 2023-01-20T16:36:03.675031419+01:00[Europe/Amsterdam] [iat=1674228963675 password="********" username="pmlopes@gmail.com"]
    // 2023-01-20T16:36:03.675366132+01:00[Europe/Amsterdam] [iat=1674228963675 password="********" username="*****************"]; sig=VluYJtniwx3os+SQjNdeIhw9pqMeGS4H9EXhXv5QOdY=
  }

  @Test
  public void testAsync(TestContext should) {
    final Async test = should.async();
    AuditLogger log = AuditLogger.instance();

    log.succeeded(Marker.EVENT);

    // 2023-01-20T16:45:25.388942642+01:00[Europe/Amsterdam] -

    final Promise<Void> promise = Promise.promise();

    rule.vertx()
      .executeBlocking(task -> {
        try {
          Thread.sleep(100);
          task.complete();
        } catch (InterruptedException e) {
          should.fail(e);
        }
      }, op -> promise.complete());

    promise.future()
      // this is what we need to add to the existing APIs
      .andThen(log.handle(Marker.SECURITY, new StructuredData(new UsernamePasswordCredentials("pmlopes@gmail.com", "\b\b\bpassword"))))
      // here is what happens at the user code (outside the framework code)
      .onFailure(should::fail)
      .onSuccess(v -> {
        test.complete();
      });

    // 2023-01-20T16:45:25.513330147+01:00[Europe/Amsterdam] [iat=1674229525412 password="***********" username="pmlopes@gmail.com"]; sig=O2RCmXbFqnfOzp2ZFc3GAa7IXza0ZwZsSZ/F4kd3RYk=

    // Note the time difference
  }
}
