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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.user.User;
import org.junit.Assert;

import java.util.function.Function;

public class TestUtils {

  public static <T> void testJsonCodec(T authorization, Function<T, JsonObject> toJsonConverter,
                                       Function<JsonObject, T> fromJsonConverter) {
    Assert.assertNotNull(authorization);
    JsonObject json = toJsonConverter.apply(authorization);
    T otherAuthorization = fromJsonConverter.apply(json);
    Assert.assertEquals(authorization, otherAuthorization);
  }

  public static AuthorizationContext getTestAuthorizationContext() {
    return getTestAuthorizationContext(User.fromName("dummy user"));
  }

  public static AuthorizationContext getTestAuthorizationContext(User user) {
    return null;
  }

}
