package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public class OAuth2APIResult {

  private final int statusCode;
  private final MultiMap headers;
  private final Buffer body;


  public OAuth2APIResult(int statusCode, MultiMap headers, Buffer body) {
    this.headers = headers;
    this.body = body;
    this.statusCode = statusCode;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public MultiMap getHeaders() {
    return headers;
  }

  public Buffer getBody() {
    return body;
  }

  public JsonObject getJsonObject() {
    return new JsonObject(body.toString());
  }

  public JsonArray getJsonArray() {
    return new JsonArray(body.toString());
  }

  public boolean is(String contentType) {
    if (headers != null) {
      if (contentType.equals(headers.get("Content-Type"))) {
        return true;
      }
    }
    return false;
  }
}
