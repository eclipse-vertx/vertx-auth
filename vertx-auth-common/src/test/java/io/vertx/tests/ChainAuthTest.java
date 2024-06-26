package io.vertx.tests;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.ChainAuth;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class ChainAuthTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void emptyTestAny(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.any();

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
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

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
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

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(createUser(new JsonObject()));
    });

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
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

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(createUser(new JsonObject()));
    });

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
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

    auth.add(credentials -> {
      // always Fail
      return Future.failedFuture("some error/bad auth");
    });

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(createUser(new JsonObject().put("provider", 2)));
    });

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
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

    auth.add(credentials -> {
      // always Fail
      return Future.failedFuture("some error/bad auth");
    });

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(createUser(new JsonObject().put("provider", 2)));
    });

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
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

    auth.add(credentials -> {
      // always Fail
      return Future.failedFuture("some error/bad auth");
    });

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(createUser(new JsonObject().put("provider", 2)));
    });

    auth.add(credentials -> {
      return Future.failedFuture("should not be called");
    });

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
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

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(User.create(new JsonObject().put("provider", 1), new JsonObject().put("attributeOne", "one")));
    });

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(User.create(new JsonObject().put("provider", 2), new JsonObject().put("attributeTwo", "two")));
    });

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
        if (res.succeeded()) {
          User result = res.result();
          should.assertNotNull(result);
          should.assertEquals(2, res.result().principal().getInteger("provider"));
          should.assertEquals("one", res.result().attributes().getString("attributeOne"));
          should.assertEquals("two", res.result().attributes().getString("attributeTwo"));
          test.complete();
        } else {
          should.fail();
        }
      });
  }

  private User createUser(final JsonObject principal) {
    return User.create(principal);
  }

  @Test
  public void matchAllMergeSameKeyTest(TestContext should) {
    final Async test = should.async();
    ChainAuth auth = ChainAuth.all();

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(User.create(new JsonObject().put("provider", 1), new JsonObject().put("attribute", "one")));
    });

    auth.add(credentials -> {
      // always OK
      return Future.succeededFuture(User.create(new JsonObject().put("provider", 2), new JsonObject().put("attribute", "two")));
    });

    auth.authenticate(new TokenCredentials("xyz"))
      .onComplete(res -> {
        if (res.succeeded()) {
          User result = res.result();
          should.assertNotNull(result);
          should.assertEquals(2, res.result().principal().getInteger("provider"));
          should.assertEquals(new JsonArray().add("one").add("two"), res.result().attributes().getValue("attribute"));
          test.complete();
        } else {
          should.fail();
        }
      });
  }
}
