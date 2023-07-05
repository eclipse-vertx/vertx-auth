package io.vertx.ext.auth.impl;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class UserConverterTest {

  @Test
  public void encode_UserImpl_defaultCtor() {
    JsonObject json = UserConverter.encode(new UserImpl());
    assertNull(json.getValue("principal"));
    assertFalse(json.containsKey("authorizations"));
    assertNull(json.getValue("attributes"));
  }

  @Test
  public void decode_UserImpl_defaultCtor() {
    UserImpl user = new UserImpl();
    JsonObject json = UserConverter.encode(user);
    User decoded = UserConverter.decode(json);
    assertNotNull(decoded);
  }
}
