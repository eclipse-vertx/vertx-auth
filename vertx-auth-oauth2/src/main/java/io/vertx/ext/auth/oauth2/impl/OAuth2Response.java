package io.vertx.ext.auth.oauth2.impl;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public class OAuth2Response implements io.vertx.ext.auth.oauth2.OAuth2Response {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2Response.class);
  private final int statusCode;
  private final MultiMap headers;
  private final Buffer body;


  public OAuth2Response(int statusCode, MultiMap headers, Buffer body) {
    LOG.debug("New response: statusCode: "+ statusCode );
    this.headers = headers;
    this.body = body;
    this.statusCode = statusCode;
  }

  public int statusCode() {
    return statusCode;
  }

  public MultiMap headers() {
    return headers;
  }

  public String getHeader(String header) {
    if (headers != null) {
      return headers.get(header);
    }
    return null;
  }

  public Buffer body() {
    return body;
  }

  @Override
  public @Nullable JsonObject jsonObject() {
    return new JsonObject(body);
  }

  @Override
  public @Nullable JsonArray jsonArray() {
    return new JsonArray(body);
  }

  public boolean is(String contentType) {
    if (headers != null) {
      String header = headers.get("Content-Type");
      if (header != null) {
        int sep = header.indexOf(';');
        // exclude charset
        if (sep != -1) {
          header = header.substring(0, sep).trim();
        }

        return contentType.equalsIgnoreCase(header);
      }
    }
    return false;
  }
}
