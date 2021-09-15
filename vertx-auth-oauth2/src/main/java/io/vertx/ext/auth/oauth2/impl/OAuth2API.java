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
import io.vertx.core.json.JsonObject;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.impl.http.SimpleHttpResponse;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Paulo Lopes
 */
public class OAuth2API {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2API.class);
  private static final Pattern MAX_AGE = Pattern.compile("max-age=\"?(\\d+)\"?");

  private final HttpClient client;
  private final OAuth2Options config;

  public OAuth2API(Vertx vertx, OAuth2Options config) {
    this.config = config;
    this.client = vertx.createHttpClient(config.getHttpClientOptions());
  }

  /**
   * Retrieve the public server JSON Web Key (JWK) required to verify the authenticity of issued ID and access tokens.
   */
  public void jwkSet(Handler<AsyncResult<JsonObject>> handler) {
    final JsonObject headers = new JsonObject();
    // specify preferred accepted content type, according to https://tools.ietf.org/html/rfc7517#section-8.5
    // there's a specific media type for this resource: application/jwk-set+json but we also allow plain application/json
    headers.put("Accept", "application/jwk-set+json, application/json");

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

        final SimpleHttpResponse reply = res.result();

        if (reply.body() == null || reply.body().length() == 0) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        JsonObject json;

        if (reply.is("application/jwk-set+json") || reply.is("application/json")) {
          try {
            json = new JsonObject(reply.body());
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
            // process the cache headers as recommended by: https://openid.net/specs/openid-connect-core-1_0.html#RotateEncKeys
            List<String> cacheControl = reply.headers().getAll(HttpHeaders.CACHE_CONTROL);
            if (cacheControl != null) {
              for (String header : cacheControl) {
                // we need at least "max-age="
                if (header.length() > 8) {
                  Matcher match = MAX_AGE.matcher(header);
                  if (match.find()) {
                    try {
                      json.put("maxAge", Long.valueOf(match.group(1)));
                      break;
                    } catch (RuntimeException e) {
                      // ignore bad formed headers
                    }
                  }
                }
              }
            }
            handler.handle(Future.succeededFuture(json));
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
  public String authorizeURL(JsonObject params) {
    final JsonObject query = params.copy();

    if (config.getFlow() != OAuth2FlowType.AUTH_CODE) {
      throw new IllegalStateException("authorization URL cannot be computed for non AUTH_CODE flow");
    }

    if (query.containsKey("scopes")) {
      // scopes have been passed as a list so the provider must generate the correct string for it
      query.put("scope", String.join(config.getScopeSeparator(), query.getJsonArray("scopes").getList()));
      query.remove("scopes");
    }

    query.put("response_type", "code");
    String clientId = config.getClientId();
    if (clientId != null) {
      query.put("client_id", clientId);
    } else {
      query
        .put("client_assertion_type", config.getClientAssertionType())
        .put("client_assertion", config.getClientAssertion());
    }

    final String path = config.getAuthorizationPath();
    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;

    return url + '?' + SimpleHttpClient.jsonToQuery(query).toString();
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

    final boolean confidentialClient = config.getClientId() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientId() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
    }

    // Enable the system to send authorization params in the body (for example github does not require to be in the header)
    final JsonObject form = params.copy();
    if (config.getExtraParameters() != null) {
      form.mergeIn(config.getExtraParameters());
    }

    form.put("grant_type", grantType);

    if (!confidentialClient) {
      String clientId = config.getClientId();
      if (clientId != null) {
        form.put("client_id", clientId);
      } else {
        form
          .put("client_assertion_type", config.getClientAssertionType())
          .put("client_assertion", config.getClientAssertion());
      }
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = SimpleHttpClient.jsonToQuery(form);

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

        final SimpleHttpResponse reply = res.result();

        if (reply.body() == null || reply.body().length() == 0) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = new JsonObject(reply.body());
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            json = SimpleHttpClient.queryToJson(reply.body());
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

    final boolean confidentialClient = config.getClientId() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientId() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
    }

    final JsonObject form = new JsonObject()
      .put("token", token)
      // optional param from RFC7662
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = SimpleHttpClient.jsonToQuery(form);
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

        final SimpleHttpResponse reply = res.result();

        if (reply.body() == null || reply.body().length() == 0) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = new JsonObject(reply.body());
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            json = SimpleHttpClient.queryToJson(reply.body());
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

    final boolean confidentialClient = config.getClientId() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientId() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
    }

    final JsonObject form = new JsonObject();

    form
      .put("token", token)
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = SimpleHttpClient.jsonToQuery(form);
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

        final SimpleHttpResponse reply = res.result();

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
  public void userInfo(String accessToken, JWT jwt, Handler<AsyncResult<JsonObject>> handler) {
    final JsonObject headers = new JsonObject();
    final JsonObject extraParams = config.getUserInfoParameters();
    String path = config.getUserInfoPath();

    if (path == null) {
      handler.handle(Future.failedFuture("userInfo path is not configured"));
      return;
    }

    if (extraParams != null) {
      path += "?" + SimpleHttpClient.jsonToQuery(extraParams);
    }

    headers.put("Authorization", "Bearer " + accessToken);
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/jwt,application/x-www-form-urlencoded;q=0.9");

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

        final SimpleHttpResponse reply = fetch.result();
        // userInfo is expected to be an object
        JsonObject userInfo;

        if (reply.is("application/json")) {
          try {
            // userInfo is expected to be an object
            userInfo = new JsonObject(reply.body());
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/jwt")) {
          try {
            // userInfo is expected to be a JWT
            userInfo = jwt.decode(reply.body().toString(StandardCharsets.UTF_8));
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            // attempt to convert url encoded string to json
            userInfo = SimpleHttpClient.queryToJson(reply.body());
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
  public String endSessionURL(String idToken, JsonObject params) {
    final String path = config.getLogoutPath();

    if (path == null) {
      // we can't generate anything, there's no configured logout path
      return null;
    }

    final JsonObject query = params.copy();

    if (idToken != null) {
      query.put("id_token_hint", idToken);
    }

    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;

    return url + '?' + SimpleHttpClient.jsonToQuery(query).toString();
  }

  /**
   * Sign out an end-user.
   *
   * see:
   */
  public void logout(String accessToken, String refreshToken, Handler<AsyncResult<Void>> callback) {
    final JsonObject headers = new JsonObject();

    headers.put("Authorization", "Bearer " + accessToken);

    final JsonObject form = new JsonObject();

    form.put("client_id", config.getClientId());

    if (config.getClientSecret() != null) {
      form.put("client_secret", config.getClientSecret());
    }

    if (refreshToken != null) {
      form.put("refresh_token", refreshToken);
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = SimpleHttpClient.jsonToQuery(form);
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

  public void fetch(HttpMethod method, String path, JsonObject headers, Buffer payload, Handler<AsyncResult<SimpleHttpResponse>> callback) {

    if (path == null || path.length() == 0) {
      // and this can happen as it is a config option that is dependent on the provider
      callback.handle(Future.failedFuture("Invalid path"));
      return;
    }

    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;
    LOG.debug("Fetching URL: " + url);

    RequestOptions options = new RequestOptions().setMethod(method).setAbsoluteURI(url);

    // apply the provider required headers
    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      for (Map.Entry<String, Object> kv : tmp) {
        options.addHeader(kv.getKey(), (String) kv.getValue());
      }
    }

    if (headers != null) {
      for (Map.Entry<String, Object> kv : headers) {
        options.addHeader(kv.getKey(), (String) kv.getValue());
      }
    }

    // specific UA
    if (config.getUserAgent() != null) {
      options.addHeader("User-Agent", config.getUserAgent());
    }

    if (method != HttpMethod.POST && method != HttpMethod.PATCH && method != HttpMethod.PUT) {
      payload = null;
    }

    // create a request
    makeRequest(options, payload, callback);
  }

  private void makeRequest(RequestOptions options, Buffer payload, final Handler<AsyncResult<SimpleHttpResponse>> callback) {
    client.request(options, request -> {
      if (request.failed()) {
        callback.handle(Future.failedFuture(request.cause()));
        return;
      }

      final HttpClientRequest req = request.result();

      final Handler<AsyncResult<HttpClientResponse>> resultHandler = send -> {
        if (send.failed()) {
          callback.handle(Future.failedFuture(send.cause()));
          return;
        }

        final HttpClientResponse res = send.result();

        // read the body regardless
        res.body(body -> {
          if (body.succeeded()) {
            final SimpleHttpResponse oauth2res = new SimpleHttpResponse(res.statusCode(), res.headers(), body.result());
            if (res.statusCode() < 200 || res.statusCode() >= 300) {
              if (oauth2res.body() == null || oauth2res.body().length() == 0) {
                callback.handle(Future.failedFuture(res.statusMessage()));
              } else {
                if (oauth2res.is("application/json")) {
                  // if value is json, extract error, error_descriptions
                  try {
                    JsonObject error = oauth2res.jsonObject();
                    if (error.containsKey("error")) {
                      if (error.containsKey("error_description")) {
                        callback.handle(Future.failedFuture(error.getString("error") + ": " + error.getString("error_description")));
                      } else {
                        callback.handle(Future.failedFuture(error.getString("error")));
                      }
                      return;
                    }
                  } catch (RuntimeException e) {
                    // ignore, we can't parse the json
                  }
                }
                callback.handle(Future.failedFuture(res.statusMessage() + ": " + oauth2res.body()));
              }
            } else {
              callback.handle(Future.succeededFuture(oauth2res));
            }
          } else {
            callback.handle(Future.failedFuture(body.cause()));
          }
        });
      };

      // send
      if (payload != null) {
        req.send(payload, resultHandler);
      } else {
        req.send(resultHandler);
      }
    });
  }

  public static void processNonStandardHeaders(JsonObject json, SimpleHttpResponse reply, String sep) {
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
