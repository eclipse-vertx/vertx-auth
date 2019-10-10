package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AndAuthorization;
import io.vertx.ext.auth.Authorization;

public class AndAuthorizationConverter {

  private final static String FIELD_TYPE = "type";
  private final static String TYPE_AND_AUTHORIZATION = "and";
  private final static String FIELD_AUTHORIZATIONS = "authorizations";

  public final static JsonObject encode(AndAuthorization value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject result = new JsonObject();
    result.put(FIELD_TYPE, TYPE_AND_AUTHORIZATION);
    JsonArray authorizations = new JsonArray();
    result.put(FIELD_AUTHORIZATIONS, authorizations);
    for (Authorization authorization : value.getAuthorizations()) {
      authorizations.add(AuthorizationConverter.encode(authorization));
    }
    return result;
  }

  public final static AndAuthorization decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    if (TYPE_AND_AUTHORIZATION.equals(json.getString(FIELD_TYPE))) {
      AndAuthorization result = AndAuthorization.create();
      JsonArray authorizations = json.getJsonArray(FIELD_AUTHORIZATIONS);
      for (int i = 0; i < authorizations.size(); i++) {
        JsonObject authorization = authorizations.getJsonObject(i);
        result.addAuthorization(AuthorizationConverter.decode(authorization));
      }
      return result;
    }
    return null;
  }

}
