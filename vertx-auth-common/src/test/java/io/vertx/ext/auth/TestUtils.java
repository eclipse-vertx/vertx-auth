/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth;

import java.util.function.Function;

import org.junit.Assert;

import io.vertx.core.json.JsonObject;

public class TestUtils {

  public final static <T> void testJsonCodec(T authorization, Function<T, JsonObject> toJsonConverter,
      Function<JsonObject, T> fromJsonConverter) {
    Assert.assertNotNull(authorization);
    JsonObject json = toJsonConverter.apply(authorization);
    T otherAuthorization = fromJsonConverter.apply(json);
    Assert.assertEquals(authorization, otherAuthorization);
  }

  public final static AuthorizationContext getTestAuthorizationContext() {
    return getTestAuthorizationContext(User.create(new JsonObject().put("username", "dummy user")));
  }

  public final static AuthorizationContext getTestAuthorizationContext(User user) {
    return null;
  }

}
