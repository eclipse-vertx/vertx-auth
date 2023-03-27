
package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.pointer.JsonPointer;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Attribute;

import java.util.Objects;

public class AttributeImpl implements Attribute {

  enum Type {
    IN,
    EQ,
    NE
  }

  private final JsonPointer pointer;
  private Type type;
  private Object value;

  public AttributeImpl(JsonObject json) {
    Objects.requireNonNull(json, "json cannot be null");
    this.pointer = JsonPointer.from(json.getString("pointer"));
    this.type = json.containsKey("type") ? Type.valueOf(json.getString("type").toUpperCase()) : null;
    this.value = json.getValue("value");
  }

  public AttributeImpl(String pointer) {
    Objects.requireNonNull(pointer, "pointer cannot be null");
    this.pointer = JsonPointer.from(pointer);
  }

  @Override
  public Attribute in(Object value) {
    Objects.requireNonNull(value, "value cannot be null");
    this.type = Type.IN;
    this.value = value;
    return this;
  }

  @Override
  public Attribute eq(Object value) {
    Objects.requireNonNull(value, "value cannot be null");
    this.type = Type.EQ;
    this.value = value;
    return this;
  }

  @Override
  public Attribute ne(Object value) {
    Objects.requireNonNull(value, "value cannot be null");
    this.type = Type.NE;
    this.value = value;
    return this;
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
      case IN:
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
    final JsonObject json = new JsonObject()
      .put("pointer", pointer.toString());

    if (type != null) {
      json
        .put("type", type.name().toLowerCase());
    }

    if (value != null) {
      json
        .put("type", value);
    }

    return json;
  }
}
