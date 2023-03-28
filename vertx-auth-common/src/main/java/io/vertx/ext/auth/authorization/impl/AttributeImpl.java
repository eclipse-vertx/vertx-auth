
package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.pointer.JsonPointer;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Attribute;

import java.util.Objects;
import java.util.Set;

public class AttributeImpl implements Attribute {

  private final JsonPointer pointer;
  private final Operator type;
  private final Object value;

  public AttributeImpl(String pointer, JsonObject json) {
    Objects.requireNonNull(json, "json cannot be null");
    this.pointer = JsonPointer.from(pointer);
    Set<String> keys = json.fieldNames();
    if (keys.size() != 1) {
      throw new IllegalArgumentException("json must have exactly one field");
    }
    String key = keys.stream().findFirst().get();
    this.type = Operator.valueOf(key.toUpperCase());
    this.value = json.getValue(key);
  }

  public AttributeImpl(String pointer, Operator operator, Object value) {
    Objects.requireNonNull(pointer, "pointer cannot be null");
    this.pointer = JsonPointer.from(pointer);
    this.type = operator;
    this.value = Objects.requireNonNull(value, "value cannot be null");
  }

  @Override
  public boolean match(User user) {
    if (type == null) {
      return false;
    }

    final JsonObject ctx = new JsonObject()
      .put("principal", user.principal())
      .put("attributes", user.attributes());

    Object obj = pointer.queryJson(ctx);

    switch (type) {
      case HAS:
        if (obj instanceof JsonArray) {
          return ((JsonArray) obj).contains(value);
        }
        if (obj instanceof JsonObject) {
          return ((JsonObject) obj).containsKey((String) value);
        }
        break;
      case EQ:
        return Objects.equals(obj, value);
      case NE:
        return !Objects.equals(obj, value);
    }

    return false;
  }

  @Override
  public JsonObject toJson() {
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
