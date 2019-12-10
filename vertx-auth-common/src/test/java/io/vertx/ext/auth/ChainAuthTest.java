package io.vertx.ext.auth;

import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class ChainAuthTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void emptyTestAny(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.any();

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        should.fail();
      } else {
        test.complete();
      }
    });
  }

  @Test
  public void emptyTestAll(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.all();

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        should.fail();
      } else {
        test.complete();
      }
    });
  }

  @Test
  public void singleTestAny(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.any();

    auth.add((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject())));
    });

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        test.complete();
      } else {
        should.fail();
      }
    });
  }

  @Test
  public void singleTestAll(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.all();

    auth.add((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject())));
    });

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        test.complete();
      } else {
        should.fail();
      }
    });
  }

  @Test
  public void multipleTestAny(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.any();

    auth.add((authInfo, res) -> {
      // always Fail
      res.handle(Future.failedFuture("some error/bad auth"));
    });

    auth.add((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject().put("provider", 2))));
    });

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        should.assertEquals(2, res.result().principal().getInteger("provider"));
        test.complete();
      } else {
        should.fail();
      }
    });
  }

  @Test
  public void multipleTestAll(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.all();

    auth.add((authInfo, res) -> {
      // always Fail
      res.handle(Future.failedFuture("some error/bad auth"));
    });

    auth.add((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject().put("provider", 2))));
    });

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        should.assertEquals(2, res.result().principal().getInteger("provider"));
        should.fail();
      } else {
        test.complete();
      }
    });
  }

  @Test
  public void stopOnMatchTest(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.any();

    auth.add((authInfo, res) -> {
      // always Fail
      res.handle(Future.failedFuture("some error/bad auth"));
    });

    auth.add((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject().put("provider", 2))));
    });

    auth.add((authInfo, res) -> should.fail("should not be called"));

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        should.assertEquals(2, res.result().principal().getInteger("provider"));
        test.complete();
      } else {
        should.fail();
      }
    });
  }

  @Test
  public void matchAllTest(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.all();

    auth.add((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject().put("provider", 1))));
    });

    auth.add((authInfo, res) -> {
      // always OK
      res.handle(Future.succeededFuture(createUser(new JsonObject().put("provider", 2))));
    });

    auth.authenticate(new JsonObject(), res -> {
      if (res.succeeded()) {
        should.assertEquals(2, res.result().principal().getInteger("provider").intValue());
        test.complete();
      } else {
        should.fail();
      }
    });
  }

  private User createUser(final JsonObject principal) {
    return User.create(principal);
  }
}
