package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.oauth2.OAuth2Response;

public class OAuth2ResponseImpl implements OAuth2Response {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2ResponseImpl.class);
  private final int statusCode;
  private final MultiMap headers;
  private final Buffer body;


  public OAuth2ResponseImpl(int statusCode, MultiMap headers, Buffer body) {
    LOG.info("New response: statusCode: "+ statusCode );
    this.headers = headers;
    this.body = body;
    this.statusCode = statusCode;
  }

  @Override
  public int statusCode() {
    return statusCode;
  }

  @Override
  public MultiMap headers() {
    return headers;
  }

  @Override
  public String getHeader(String header) {
    if (headers != null) {
      return headers.get(header);
    }
    return null;
  }

  @Override
  public Buffer body() {
    return body;
  }

  @Override
  public JsonObject jsonObject() {
    return new JsonObject(body.toString());
  }

  @Override
  public JsonArray jsonArray() {
    return new JsonArray(body.toString());
  }

  @Override
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
