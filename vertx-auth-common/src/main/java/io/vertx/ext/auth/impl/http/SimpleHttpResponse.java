/*
 * Copyright 2015 Red Hat, Inc.
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
package io.vertx.ext.auth.impl.http;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public final class SimpleHttpResponse {

  private final int statusCode;
  private final MultiMap headers;
  private final Buffer body;

  public SimpleHttpResponse(int statusCode, MultiMap headers, Buffer body) {
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

  public @Nullable String getHeader(String header) {
    if (headers != null) {
      return headers.get(header);
    }
    return null;
  }

  public @Nullable Buffer body() {
    return body;
  }

  public @Nullable JsonObject jsonObject() {
    if (body == null) {
      return null;
    }
    return new JsonObject(body);
  }

  public @Nullable JsonArray jsonArray() {
    if (body == null) {
      return null;
    }
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
