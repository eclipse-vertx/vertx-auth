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
package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Map;

/**
 * @author Paulo Lopes
 */
public class OAuth2API {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2API.class);

  public static void fetch(Vertx vertx, OAuth2ClientOptions config, HttpMethod method, String path, JsonObject headers, Buffer payload, Handler<AsyncResult<OAuth2Response>> callback) {

    if (path == null || path.length() == 0) {
      // and this can happen as it is a config option that is dependent on the provider
      callback.handle(Future.failedFuture("Invalid path"));
      return;
    }

    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;
    LOG.info("Fetching URL: " + url);

    // create a request
    final HttpClientRequest request = makeRequest(vertx, config, method, url, callback);

    // apply the provider required headers
    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      for (Map.Entry<String, Object> kv : tmp) {
        request.putHeader(kv.getKey(), (String) kv.getValue());
      }
    }

    if (headers != null) {
      for (Map.Entry<String, Object> kv : headers) {
        request.putHeader(kv.getKey(), (String) kv.getValue());
      }
    }

    // specific UA
    if (config.getUserAgent() != null) {
      request.putHeader("User-Agent", config.getUserAgent());
    }

    if (payload != null) {
      if (method == HttpMethod.POST || method == HttpMethod.PATCH || method == HttpMethod.PUT) {
        request.putHeader("Content-Length", Integer.toString(payload.length()));
        request.write(payload);
      }
    }

    // Make sure the request is ended when you're done with it
    request.end();
  }

  public static HttpClientRequest makeRequest(Vertx vertx, HttpClientOptions options, HttpMethod method, String uri, final Handler<AsyncResult<OAuth2Response>> callback) {
    HttpClient client;

    try {
      URL url = new URL(uri);
      boolean isSecure = "https".equalsIgnoreCase(url.getProtocol());
      String host = url.getHost();
      int port = url.getPort();

      if (port == -1) {
        if (isSecure) {
          port = 443;
        } else {
          port = 80;
        }
      }

      client = vertx.createHttpClient(new HttpClientOptions(options)
        .setSsl(isSecure)
        .setDefaultHost(host)
        .setDefaultPort(port));

    } catch (MalformedURLException e) {
      throw new RuntimeException(e);
    }

    final HttpClientRequest request = client.requestAbs(method, uri, resp -> {
      resp.exceptionHandler(t -> {
        callback.handle(Future.failedFuture(t));
        client.close();
      });

      resp.bodyHandler(body -> {
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
          if (body == null || body.length() == 0) {
            callback.handle(Future.failedFuture(resp.statusMessage()));
          } else {
            callback.handle(Future.failedFuture(resp.statusMessage() + ": " + body.toString()));
          }
        } else {
          callback.handle(Future.succeededFuture(new OAuth2ResponseImpl(resp.statusCode(), resp.headers(), body)));
        }
        client.close();
      });
    });

    request.exceptionHandler(t -> {
      callback.handle(Future.failedFuture(t));
      client.close();
    });

    return request;
  }

  public static String stringify(JsonObject json) {
    StringBuilder sb = new StringBuilder();
    try {
      for (Map.Entry<String, ?> kv : json) {
        sb.append(URLEncoder.encode(kv.getKey(), "UTF-8"));
        sb.append('=');
        Object v = kv.getValue();
        if (v != null) {
          sb.append(URLEncoder.encode(v.toString(), "UTF-8"));
        }
        sb.append('&');
      }
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }

    // exclude the last amp
    if (sb.length() > 0) {
      sb.setLength(sb.length() - 1);
    }

    return sb.toString();
  }

  public static JsonObject queryToJSON(String query) throws UnsupportedEncodingException {
    final JsonObject json = new JsonObject();
    final String[] pairs = query.split("&");
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

  public static void processNonStandardHeaders(JsonObject json, OAuth2Response reply, String sep) {
    // inspect the response headers for the non-standard:
    // X-OAuth-Scopes and X-Accepted-OAuth-Scopes
    final String xOAuthScopes = reply.getHeader("X-OAuth-Scopes");
    final String xAcceptedOAuthScopes = reply.getHeader("X-Accepted-OAuth-Scopes");

    if (xOAuthScopes != null) {
      LOG.debug("Received non-standard X-OAuth-Scopes: "+ xOAuthScopes);
      if (json.containsKey("scope")) {
        json.put("scope", json.getString("scope") + sep + xOAuthScopes);
      } else {
        json.put("scope", xOAuthScopes);
      }
    }

    if (xAcceptedOAuthScopes != null) {
      LOG.debug("Received non-standard X-Accepted-OAuth-Scopes: "+ xAcceptedOAuthScopes);
      json.put("acceptedScopes", xAcceptedOAuthScopes);
    }
  }

}
