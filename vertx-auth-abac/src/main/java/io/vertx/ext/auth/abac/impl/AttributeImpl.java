/*
 * Copyright 2014 Red Hat, Inc.
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
package io.vertx.ext.auth.abac.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.pointer.JsonPointer;
import io.vertx.ext.auth.user.User;
import io.vertx.ext.auth.abac.Attribute;

import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

public class AttributeImpl implements Attribute {

  private final JsonPointer pointer;
  private final Operator type;
  private final Object value;
  private final Function<User, Boolean> function;

  public AttributeImpl(String pointer, JsonObject json) {
    Objects.requireNonNull(json, "json cannot be null");
    this.pointer = JsonPointer.from(pointer);
    Set<String> keys = json.fieldNames();
    if (keys.size() != 1) {
      throw new IllegalArgumentException("json must have exactly one field");
    }
    String key = keys.stream().findFirst().get();
    this.type = Operator.valueOf(key.toUpperCase());
    if (this.type == Operator.FN) {
      throw new IllegalArgumentException("json policy does not allow FN operator");
    }
    this.value = json.getValue(key);
    this.function = null;
  }

  public AttributeImpl(String pointer, Operator operator, Object value) {
    Objects.requireNonNull(pointer, "pointer cannot be null");
    this.pointer = JsonPointer.from(pointer);
    this.type = operator;
    this.value = Objects.requireNonNull(value, "value cannot be null");
    this.function = null;
  }

  public AttributeImpl(Function<User, Boolean> function) {
    this.pointer = null;
    this.type = Operator.FN;
    this.function = Objects.requireNonNull(function, "function cannot be null");
    this.value = null;
  }

  @Override
  public boolean match(User user) {
    if (type == null) {
      return false;
    }

    JsonObject ctx;
    Object obj;

    switch (type) {
      case HAS:
        ctx = new JsonObject()
          .put("principal", user.principal())
          .put("attributes", user.attributes());
        obj = pointer.queryJson(ctx);

        if (obj instanceof JsonArray) {
          return ((JsonArray) obj).contains(value);
        }
        if (obj instanceof JsonObject) {
          return ((JsonObject) obj).containsKey((String) value);
        }
        break;
      case EQ:
        ctx = new JsonObject()
          .put("principal", user.principal())
          .put("attributes", user.attributes());
        obj = pointer.queryJson(ctx);

        return Objects.equals(obj, value);
      case NE:
        ctx = new JsonObject()
          .put("principal", user.principal())
          .put("attributes", user.attributes());
        obj = pointer.queryJson(ctx);

        return !Objects.equals(obj, value);
      case FN:
        return function.apply(user);
    }

    return false;
  }

  @Override
  public JsonObject toJson() {
    if (type == Operator.FN) {
      throw new UnsupportedOperationException("Cannot serialize custom attribute function");
    }

    if (type != null && value != null) {
      return new JsonObject()
        .put(
          pointer.toString(),
          new JsonObject()
            .put(type.name().toLowerCase(), value));
    }

    return null;
  }
}
