package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.User;

public class UserConverter {

  private final static String FIELD_PRINCIPAL = "principal";
  private final static String FIELD_AUTHORIZATIONS = "authorizations";

  public final static JsonObject encode(User value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject json = new JsonObject();
    json.put(FIELD_PRINCIPAL, value.principal());
    JsonArray authorizations = new JsonArray();
    for (Authorization authorization : value.authorizations()) {
      authorizations.add(AuthorizationConverter.encode(authorization));
    }
    json.put(FIELD_AUTHORIZATIONS, authorizations);
    return json;
  }

  public final static User decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    JsonObject principal = json.getJsonObject(FIELD_PRINCIPAL);
    User user = User.create((JsonObject) principal);
    // authorizations
    JsonArray authorizations = json.getJsonArray(FIELD_AUTHORIZATIONS);
    for (int i = 0; i < authorizations.size(); i++) {
      user.authorizations().add(AuthorizationConverter.decode(authorizations.getJsonObject(i)));
    }
    return user;
  }

}
