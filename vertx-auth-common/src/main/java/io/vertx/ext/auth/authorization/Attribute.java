/*
 * Copyright 2023 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.authorization;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.impl.AttributeImpl;

/**
 * An attribute is a simple matcher for policies. A Attribute is created from a JsonPointer to the {@link User} object
 * and a logical operator:
 *
 * <ul>
 *   <li>{@link #has(Object)} - the value must be in the JsonArray or JsonObject</li>
 *   <li>{@link #eq(Object)} - the value must be equals to the pointed location</li>
 *   <li>{@link #ne(Object)} - the value must not be equals to the pointed location</li>
 * </ul>
 */
@VertxGen
public interface Attribute {

  static Attribute create(String pointer) {
    return new AttributeImpl(pointer);
  }

  /**
   * Verifies wheather or not the attribute matches the specified. The value must be in the JsonArray or JsonObject
   * referenced by the json pointer.
   */
  @Fluent
  Attribute has(Object value);

  /**
   * Verifies wheather or not the attribute matches the specified. The value must be equal to the value
   * referenced by the json pointer.
   */
  @Fluent
  Attribute eq(Object value);

  /**
   * Verifies wheather or not the attribute matches the specified. The value must not be equal to the value
   * referenced by the json pointer.
   */
  @Fluent
  Attribute ne(Object value);

  /**
   * Verifies wheather or not the attribute matches the specified
   * user.
   *
   * @param user the user.
   * @return true if there's a match
   */
  boolean match(User user);


  JsonObject toJson();
}
