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
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.Map;

/**
 * @author Paulo Lopes
 */
public class OAuth2API {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2API.class);

  private final HttpClient client;
  private final OAuth2ClientOptions config;

  public OAuth2API(Vertx vertx, OAuth2ClientOptions config) {
    this.config = config;
    this.client = vertx.createHttpClient(config);
  }

  /**
   * Retrieve the public server JSON Web Key (JWK) required to verify the authenticity of issued ID and access tokens.
   */
  public void jwkSet(Handler<AsyncResult<JsonArray>> handler) {
    final JsonObject headers = new JsonObject();
    // specify preferred accepted content type
    headers.put("Accept", "application/json");

    fetch(
      HttpMethod.GET,
      config.getJwkPath(),
      headers,
      null,
      res -> {
        if (res.failed()) {
          handler.handle(Future.failedFuture(res.cause()));
          return;
        }

        final OAuth2Response reply = res.result();

        if (reply.body() == null || reply.body().length() == 0) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = reply.jsonObject();
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else {
          handler.handle(Future.failedFuture("Cannot handle content type: " + reply.headers().get("Content-Type")));
          return;
        }

        try {
          if (json.containsKey("error")) {
            handler.handle(Future.failedFuture(extractErrorDescription(json)));
          } else {
            handler.handle(Future.succeededFuture(json.getJsonArray("keys")));
          }
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });
  }

  /**
   * The client sends the end-user's browser to this endpoint to request their authentication and consent. This endpoint is used in the code and implicit OAuth 2.0 flows which require end-user interaction.
   *
   * see: https://tools.ietf.org/html/rfc6749
   */
  public void authorizeURL(JsonObject params, Handler<AsyncResult<String>> handler) {
    final JsonObject query = params.copy();

    if (config.getFlow() != OAuth2FlowType.AUTH_CODE) {
      handler.handle(Future.failedFuture("authorization URL cannot be computed for non AUTH_CODE flow"));
      return;
    }

    if (query.containsKey("scopes")) {
      // scopes have been passed as a list so the provider must generate the correct string for it
      query.put("scope", String.join(config.getScopeSeparator(), query.getJsonArray("scopes").getList()));
      query.remove("scopes");
    }

    query.put("response_type", "code");
    query.put("client_id", config.getClientID());

    final String path = config.getAuthorizationPath();
    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;

    handler.handle(Future.succeededFuture(url + '?' + stringify(query)));
  }

  /**
   * Post an OAuth 2.0 grant (code, refresh token, resource owner password credentials, client credentials) to obtain an ID and / or access token.
   *
   * see: https://tools.ietf.org/html/rfc6749
   */
  public void token(String grantType, JsonObject params, Handler<AsyncResult<JsonObject>> handler) {
    // quick check and abort
    if (grantType == null) {
      handler.handle(Future.failedFuture("Token request requires a grantType other than null"));
      return;
    }

    final JsonObject headers = new JsonObject();

    final boolean confidentialClient = config.getClientID() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientID() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes()));
    }

    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    // Enable the system to send authorization params in the body (for example github does not require to be in the header)
    final JsonObject form = params.copy();
    if (config.getExtraParameters() != null) {
      form.mergeIn(config.getExtraParameters());
    }

    form.put("grant_type", grantType);

    if (!confidentialClient) {
      form.put("client_id", config.getClientID());
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));

    // specify preferred accepted content type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    fetch(
      HttpMethod.POST,
      config.getTokenPath(),
      headers,
      payload,
      res -> {
        if (res.failed()) {
          handler.handle(Future.failedFuture(res.cause()));
          return;
        }

        final OAuth2Response reply = res.result();

        if (reply.body() == null || reply.body().length() == 0) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = reply.jsonObject();
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            json = queryToJSON(reply.body().toString());
          } catch (UnsupportedEncodingException | RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else {
          handler.handle(Future.failedFuture("Cannot handle content type: " + reply.headers().get("Content-Type")));
          return;
        }

        try {
          if (json.containsKey("error")) {
            handler.handle(Future.failedFuture(extractErrorDescription(json)));
          } else {
            OAuth2API.processNonStandardHeaders(json, reply, config.getScopeSeparator());
            handler.handle(Future.succeededFuture(json));
          }
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });
  }

  /**
   * Validate an access token and retrieve its underlying authorisation (for resource servers).
   *
   * see: https://tools.ietf.org/html/rfc7662
   */
  public void tokenIntrospection(String tokenType, String token, Handler<AsyncResult<JsonObject>> handler) {
    final JsonObject headers = new JsonObject();

    final boolean confidentialClient = config.getClientID() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientID() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes()));
    }

    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject()
      .put("token", token)
      // optional param from RFC7662
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    fetch(
      HttpMethod.POST,
      config.getIntrospectionPath(),
      headers,
      payload,
      res -> {
        if (res.failed()) {
          handler.handle(Future.failedFuture(res.cause()));
          return;
        }

        final OAuth2Response reply = res.result();

        if (reply.body() == null || reply.body().length() == 0) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = reply.jsonObject();
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            json = queryToJSON(reply.body().toString());
          } catch (UnsupportedEncodingException | RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else {
          handler.handle(Future.failedFuture("Cannot handle accessToken type: " + reply.headers().get("Content-Type")));
          return;
        }

        try {
          if (json.containsKey("error")) {
            handler.handle(Future.failedFuture(extractErrorDescription(json)));
          } else {
            processNonStandardHeaders(json, reply, config.getScopeSeparator());
            handler.handle(Future.succeededFuture(json));
          }
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });
  }

  /**
   * Revoke an obtained access or refresh token.
   *
   * see: https://tools.ietf.org/html/rfc7009
   */
  public void tokenRevocation(String tokenType, String token, Handler<AsyncResult<Void>> handler) {
    if (token == null) {
      handler.handle(Future.failedFuture("Cannot revoke null token"));
      return;
    }

    final JsonObject headers = new JsonObject();

    final boolean confidentialClient = config.getClientID() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientID() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes()));
    }

    final JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject();

    form
      .put("token", token)
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    fetch(
      HttpMethod.POST,
      config.getRevocationPath(),
      headers,
      payload,
      res -> {
        if (res.failed()) {
          handler.handle(Future.failedFuture(res.cause()));
          return;
        }

        final OAuth2Response reply = res.result();

        if (reply.body() == null) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        handler.handle(Future.succeededFuture());
      });
  }

  /**
   * Retrieve profile information and other attributes for a logged-in end-user.
   *
   * see: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
   */
  public void userInfo(String accessToken, Handler<AsyncResult<JsonObject>> handler) {
    final JsonObject headers = new JsonObject();
    final JsonObject extraParams = config.getUserInfoParameters();
    String path = config.getUserInfoPath();

    if (extraParams != null) {
      path += "?" + stringify(extraParams);
    }

    headers.put("Authorization", "Bearer " + accessToken);
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    fetch(
      HttpMethod.GET,
      path,
      headers,
      null,
      fetch -> {
        if (fetch.failed()) {
          handler.handle(Future.failedFuture(fetch.cause()));
          return;
        }

        final OAuth2Response reply = fetch.result();
        // userInfo is expected to be an object
        JsonObject userInfo;

        if (reply.is("application/json")) {
          try {
            // userInfo is expected to be an object
            userInfo = reply.jsonObject();
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            // attempt to convert url encoded string to json
            userInfo = queryToJSON(reply.body().toString());
          } catch (RuntimeException | UnsupportedEncodingException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else {
          handler.handle(Future.failedFuture("Cannot handle Content-Type: " + reply.headers().get("Content-Type")));
          return;
        }

        processNonStandardHeaders(userInfo, reply, config.getScopeSeparator());
        handler.handle(Future.succeededFuture(userInfo));
      });
  }

  /**
   * The logout (end-session) endpoint is specified in OpenID Connect Session Management 1.0.
   *
   * see: https://openid.net/specs/openid-connect-session-1_0.html
   */
  public void endSessionURL(String idToken, JsonObject params, Handler<AsyncResult<String>> handler) {
    final JsonObject query = params.copy();

    if (idToken != null) {
      query.put("id_token_hint", idToken);
    }

    final String path = config.getLogoutPath();
    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;

    handler.handle(Future.succeededFuture(url + '?' + stringify(query)));
  }

  /**
   * Sign out an end-user.
   *
   * see:
   */
  public void logout(String accessToken, String refreshToken, Handler<AsyncResult<Void>> callback) {
    final JsonObject headers = new JsonObject();

    headers.put("Authorization", "Bearer " + accessToken);

    JsonObject tmp = config.getHeaders();

    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject();

    form.put("client_id", config.getClientID());

    if (config.getClientSecretParameterName() != null && config.getClientSecret() != null) {
      form.put(config.getClientSecretParameterName(), config.getClientSecret());
    }

    if (refreshToken != null) {
      form.put("refresh_token", refreshToken);
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    fetch(
      HttpMethod.POST,
      config.getLogoutPath(),
      headers,
      payload,
      res -> {
        if (res.succeeded()) {
          callback.handle(Future.succeededFuture());
        } else {
          callback.handle(Future.failedFuture(res.cause()));
        }
      });
  }

  private String extractErrorDescription(JsonObject json) {
    String description;
    Object error = json.getValue("error");
    if (error instanceof JsonObject) {
      description = ((JsonObject) error).getString("message");
    } else {
      // attempt to handle the error as a string
      try {
        description = json.getString("error_description", json.getString("error"));
      } catch (RuntimeException e) {
        description = error.toString();
      }
    }
    return description;
  }

  public void fetch(HttpMethod method, String path, JsonObject headers, Buffer payload, Handler<AsyncResult<OAuth2Response>> callback) {

    if (path == null || path.length() == 0) {
      // and this can happen as it is a config option that is dependent on the provider
      callback.handle(Future.failedFuture("Invalid path"));
      return;
    }

    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;
    LOG.debug("Fetching URL: " + url);

    // create a request
    final HttpClientRequest request = makeRequest(method, url, callback);

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

  public HttpClientRequest makeRequest(HttpMethod method, String uri, final Handler<AsyncResult<OAuth2Response>> callback) {
    final HttpClientRequest request = client.requestAbs(method, uri, ar -> {
      if (ar.succeeded()) {
        HttpClientResponse resp = ar.result();
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
        });
      } else {
        callback.handle(Future.failedFuture(ar.cause()));
      }
    });

    request.exceptionHandler(t -> callback.handle(Future.failedFuture(t)));

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
      LOG.trace("Received non-standard X-OAuth-Scopes: "+ xOAuthScopes);
      if (json.containsKey("scope")) {
        json.put("scope", json.getString("scope") + sep + xOAuthScopes);
      } else {
        json.put("scope", xOAuthScopes);
      }
    }

    if (xAcceptedOAuthScopes != null) {
      LOG.trace("Received non-standard X-Accepted-OAuth-Scopes: "+ xAcceptedOAuthScopes);
      json.put("acceptedScopes", xAcceptedOAuthScopes);
    }
  }

}
