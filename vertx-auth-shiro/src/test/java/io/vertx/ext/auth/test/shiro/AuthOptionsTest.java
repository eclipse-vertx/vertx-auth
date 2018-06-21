package io.vertx.ext.auth.test.shiro;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.shiro.ShiroAuthOptions;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class AuthOptionsTest {

  @Test
  public void testSomething() {
    ShiroAuthOptions options = new ShiroAuthOptions(
        new JsonObject().put("provider", "shiro").
            put("type", "PROPERTIES").
            put("config", new JsonObject().put("foo", "bar")));
    assertEquals(ShiroAuthRealmType.PROPERTIES, options.getType());
    assertEquals(new JsonObject().put("foo", "bar"), options.getConfig());
  }
}
