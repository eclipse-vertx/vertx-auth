package io.vertx.tests.impl;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.UserConverter;
import io.vertx.ext.auth.impl.UserImpl;
import org.junit.Test;

import static org.junit.Assert.*;

public class UserConverterTest {

  @Test
  public void encode_UserImpl_defaultCtor() {
    JsonObject json = UserConverter.encode(new UserImpl());
    assertNull(json.getValue("principal"));
    assertFalse(json.containsKey("authorizations"));
    assertNull(json.getValue("attributes"));
  }
}
