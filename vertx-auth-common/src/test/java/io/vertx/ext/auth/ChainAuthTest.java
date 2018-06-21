package io.vertx.ext.auth;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class ChainAuthTest extends VertxTestBase {

  @Test
  public void emptyTest() {
    ChainAuth auth = ChainAuth.create();

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        fail();
      } else {
        testComplete();
      }
    });
    await();
  }

  @Test
  public void singleTest() {
    ChainAuth auth = ChainAuth.create();

    auth.append((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(null)));
    });

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        testComplete();
      } else {
        fail();
      }
    });
    await();
  }

  @Test
  public void multipleTest() {
    ChainAuth auth = ChainAuth.create();

    auth.append((authInfo, res) -> {
      // always Fail
      res.handle(Future.failedFuture("some error/bad auth"));
    });

    auth.append((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject().put("provider", 2))));
    });

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        assertEquals(2, res.result().principal().getInteger("provider").intValue());
        testComplete();
      } else {
        fail();
      }
    });
    await();
  }

  @Test
  public void stopOnMatchTest() {
    ChainAuth auth = ChainAuth.create();

    auth.append((authInfo, res) -> {
      // always Fail
      res.handle(Future.failedFuture("some error/bad auth"));
    });

    auth.append((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject().put("provider", 2))));
    });

    auth.append((authInfo, res) -> fail("should not be called"));

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        assertEquals(2, res.result().principal().getInteger("provider").intValue());
        testComplete();
      } else {
        fail();
      }
    });
    await();
  }

  private User createUser(final JsonObject principal) {
    return new User() {
      @Override
      public User isAuthorized(String authority, Handler<AsyncResult<Boolean>> resultHandler) {
        return null;
      }

      @Override
      public User clearCache() {
        return null;
      }

      @Override
      public JsonObject principal() {
        return principal;
      }

      @Override
      public void setAuthProvider(AuthProvider authProvider) {

      }
    };
  }
}
