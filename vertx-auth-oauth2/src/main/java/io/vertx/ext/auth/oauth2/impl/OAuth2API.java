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

import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.Map;

/**
 * @author Paulo Lopes
 */
public class OAuth2API {

  public static void api(OAuth2AuthProviderImpl provider, HttpMethod method, String path, JsonObject params, Handler<AsyncResult<JsonObject>> callback) {
    final String url;

    if (path.startsWith("http://") || path.startsWith("https://")) {
      url = path ;
    } else {
      url = provider.getConfig().getSite() + path ;
    }

    call(provider, method, url, params, callback);
  }

  private static void call(OAuth2AuthProviderImpl provider, HttpMethod method, String uri, JsonObject params, Handler<AsyncResult<JsonObject>> callback) {

    final OAuth2ClientOptions config = provider.getConfig();

    if (config.getClientID() == null || config.getClientSecret() == null || config.getSite() == null) {
      callback.handle(Future.failedFuture("Configuration missing. You need to specify the client id, the client secret and the oauth2 server"));
      return;
    }

    final JsonObject headers = new JsonObject();

    if (params.containsKey("access_token") && !params.containsKey("client_id")) {
      headers.put("Authorization", "Bearer " + params.getString("access_token"));
      params.remove("access_token");
    } else if (config.isUseBasicAuthorizationHeader() && config.getClientID() != null && !params.containsKey("client_id")) {
      String basic = config.getClientID() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getUrlEncoder().encodeToString(basic.getBytes()));
    }

    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    JsonObject form = null;

    if (method != HttpMethod.GET) {
      form = params.copy();
    }

    if (method == HttpMethod.GET) {
      if (uri.indexOf('?') != -1) {
        uri += "&" + stringify(params);
      }
    }

    // Enable the system to send authorization params in the body (for example github does not require to be in the header)
    if (method != HttpMethod.GET && form != null) {
      form.put("client_id", config.getClientID());
      if (config.getClientSecretParameterName() != null) {
        form.put(config.getClientSecretParameterName(), config.getClientSecret());
      }
    }

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

      client = provider.getVertx().createHttpClient(new HttpClientOptions(config)
              .setSsl(isSecure)
              .setDefaultHost(host)
              .setDefaultPort(port));

    } catch (MalformedURLException e) {
      throw new RuntimeException(e);
    }

    HttpClientRequest request = client.request(method, uri, resp -> {
      resp.exceptionHandler(t -> {
        callback.handle(Future.failedFuture(t));
        client.close();
      });

      resp.bodyHandler(body -> {
        if (body == null) {
          callback.handle(Future.failedFuture("No Body"));
          client.close();
          return;
        }

        if (body.length() == 0) {
          // no body
          if (resp.statusCode() >= 400) {
            callback.handle(Future.failedFuture(resp.statusMessage()));
          } else {
            callback.handle(Future.succeededFuture());
          }
          client.close();
          return;
        }

        String contentType = resp.getHeader("Content-Type");
        int sep = contentType.indexOf(';');
        // exclude charset
        if (sep != -1) {
          contentType = contentType.substring(0, sep);
        }

        switch (contentType) {
          case "application/json":
            try {
              handleToken(resp.statusCode(), new JsonObject(body.toString()), callback);
            } catch (RuntimeException e) {
              callback.handle(Future.failedFuture(e));
            }
            break;
          case "application/x-www-form-urlencoded":
          case "text/plain":
            try {
              handleToken(resp.statusCode(), queryToJSON(body.toString()), callback);
            } catch (UnsupportedEncodingException | RuntimeException e) {
              callback.handle(Future.failedFuture(e));
            }
            break;
          default:
            callback.handle(Future.failedFuture("Cannot handle content type: " + contentType));
            break;
        }
        client.close();
      });
    });

    request.exceptionHandler(t -> {
      callback.handle(Future.failedFuture(t));
      client.close();
    });

    // write the headers
    for (Map.Entry<String, ?> kv : headers) {
      request.putHeader(kv.getKey(), kv.getValue().toString());
    }

    // specific UA
    if (config.getUserAgent() != null) {
      request.putHeader("User-Agent", config.getUserAgent());
    }

    // specify preferred content type
    request.putHeader("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    if (form != null) {
      request.putHeader("Content-Type", "application/x-www-form-urlencoded");
      final String payload = stringify(form);

      request.putHeader("Content-Length", Integer.toString(payload.length()));
      request.write(payload);
    }

    // Make sure the request is ended when you're done with it
    request.end();
  }

  private static void handleToken(final int statusCode, final JsonObject json, final Handler<AsyncResult<JsonObject>> callback) {
    if (json.containsKey("error")) {
      String error = json.getString("error");
      String description = json.getString("error_description", null);
      callback.handle(Future.failedFuture(description != null ? error + ": " + description : error));
    } else {
      // for the case there was a http protocol error
      if (statusCode >= 400) {
        callback.handle(Future.failedFuture(HttpResponseStatus.valueOf(statusCode).reasonPhrase()));
      }
      callback.handle(Future.succeededFuture(json));
    }
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
}
