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
package io.vertx.ext.auth.oauth2;


import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * A response from a fetch request.
 *
 * This class represents a secure response from a Oauth2 fetch call.
 *
 * A fetch is a simplified HTTP response from a protected resource.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface OAuth2Response {

  /**
   * the returned status code from the HTTP layer.
   *
   * @return HTTP status code
   */
  int statusCode();

  /**
   * The HTTP response headers from the HTTP layer.
   *
   * @return the HTTP headers
   */
  @Nullable
  MultiMap headers();

  /**
   * Looks up a HTTP response header by name, in case where the response is a list of headers,
   * the first one is returned.
   *
   * @param name of the header to look up
   * @return the single value for the header.
   */
  String getHeader(String name);

  /**
   * The HTTP response body as a buffer
   *
   * @return a buffer with the HTTP response body
   */
  @Nullable
  Buffer body();

  /**
   * The HTTP response body as a JsonObject
   *
   * @return a JsonObject from the HTTP response body
   */
  @Nullable
  JsonObject jsonObject();

  /**
   * The HTTP response body as a JsonArray
   *
   * @return a JsonArray from the HTTP response body
   */
  @Nullable
  JsonArray jsonArray();

  /**
   * Helper to analize the response body. The test is performed against the header Content-Type,
   * the content of the body is not analyzed.
   *
   * @param contentType a content type to test, e.g.: application/json
   * @return true if the header matches
   */
  boolean is(String contentType);
}
