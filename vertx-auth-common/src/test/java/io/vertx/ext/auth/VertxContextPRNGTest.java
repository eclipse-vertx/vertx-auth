package io.vertx.ext.auth;

import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Proxy;

import static org.junit.Assert.*;

@RunWith(VertxUnitRunner.class)
public class VertxContextPRNGTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testPRNGQuarkusContextAccessNotAllowed() {

    final Vertx vertx = rule.vertx();

    Context context = (Context) Proxy.newProxyInstance(
      VertxContextPRNGTest.class.getClassLoader(),
      new Class[] { Context.class },
      (proxy, method, methodArgs) -> {
        switch (method.getName()) {
          case "get":
          case "put":
          case "remove":
            // mimic Quarkus behavior
            throw new UnsupportedOperationException("Access to Context.put(), Context.get() and Context.remove() are forbidden as it can leak data between unrelated processing. Use Context.putLocal(), Context.getLocal() and Context.removeLocal() instead. Note that these methods can only be used from a 'duplicated' Context, and so may not be available everywhere.");
          case "owner":
            return vertx;
          case "equals":
            return false;
          default:
            return null;
        }
      });

    assertNotNull(VertxContextPRNG.current(context));
  }

}
