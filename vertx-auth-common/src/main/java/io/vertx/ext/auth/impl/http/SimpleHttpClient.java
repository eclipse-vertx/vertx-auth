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
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Map;
import java.util.function.Function;


/**
 * A simple web client that does only depend on core to avoid cyclic dependencies.
 * The client is very simple, it allows fetching/storing a resource but does not do
 * any fancy transformations.
 *
 * @author <a href="mailto:pmlopes@gmail.com>Paulo Lopes</a>
 */
public final class SimpleHttpClient {

  private final HttpClient client;
  private final String userAgent;

  public SimpleHttpClient(Vertx vertx, String userAgent, HttpClientOptions options) {
    this.client = vertx.createHttpClient(options);
    this.userAgent = userAgent;
  }

  public Future<Void> close() {
    return client.close();
  }

  public Future<SimpleHttpResponse> fetch(HttpMethod method, String url, JsonObject headers, Buffer payload) {
    if (url == null || url.length() == 0) {
      return Future.failedFuture("Invalid url");
    }

    RequestOptions options = new RequestOptions()
      .setMethod(method)
      .setAbsoluteURI(url);

    // specific UA
    if (userAgent != null) {
      options.addHeader("User-Agent", userAgent);
    }

    // apply the provider required headers
    if (headers != null) {
      for (Map.Entry<String, Object> kv : headers) {
        options.addHeader(kv.getKey(), (String) kv.getValue());
      }
    }

    if (method != HttpMethod.POST && method != HttpMethod.PATCH && method != HttpMethod.PUT) {
      payload = null;
    }

    // create a request
    return makeRequest(options, payload);
  }

  public static Buffer jsonToQuery(JsonObject json) {
    Buffer buffer = Buffer.buffer();

    try {
      for (Map.Entry<String, ?> kv : json) {
        if (buffer.length() != 0) {
          buffer.appendByte((byte) '&');
        }
        buffer.appendString(URLEncoder.encode(kv.getKey(), "UTF-8"));
        buffer.appendByte((byte) '=');
        Object v = kv.getValue();
        if (v != null) {
          buffer.appendString(URLEncoder.encode(v.toString(), "UTF-8"));
        }
      }
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }

    return buffer;
  }

  public static @Nullable JsonObject queryToJson(Buffer query) throws UnsupportedEncodingException {
    if (query == null) {
      return null;
    }
    final JsonObject json = new JsonObject();
    final String[] pairs = query.toString().split("&");
    for (String pair : pairs) {
      final int idx = pair.indexOf("=");
      final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
      final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
      if (!json.containsKey(key)) {
        json.put(key, value);
      } else {
        Object oldValue = json.getValue(key);
        JsonArray array;
        if (oldValue instanceof JsonArray) {
          array = (JsonArray) oldValue;
        } else {
          array = new JsonArray();
          array.add(oldValue);
          json.put(key, array);
        }
        if (value == null) {
          array.addNull();
        } else {
          array.add(value);
        }
      }
    }

    return json;
  }


  private Future<SimpleHttpResponse> makeRequest(RequestOptions options, Buffer payload) {
    return client.request(options)
      .compose(req -> {
        final Function<HttpClientResponse, Future<SimpleHttpResponse>> resultHandler = res -> {
          // read the body regardless
          return res.body()
            .compose(value -> {
              if (res.statusCode() < 200 || res.statusCode() >= 300) {
                if (value == null || value.length() == 0) {
                  return Future.failedFuture(res.statusMessage());
                } else {
                  return Future.failedFuture(res.statusMessage() + ": " + value);
                }
              } else {
                return Future.succeededFuture(new SimpleHttpResponse(res.statusCode(), res.headers(), value));
              }
            });
        };

        // send
        if (payload != null) {
          return req.send(payload)
            .compose(resultHandler);
        } else {
          return req.send()
            .compose(resultHandler);
        }
      });
  }
}
