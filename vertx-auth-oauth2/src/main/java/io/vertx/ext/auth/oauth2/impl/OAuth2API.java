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

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.Future;
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
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.vertx.ext.auth.impl.Codec.base64Encode;

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
  public Future<JsonObject> jwkSet() {
    final JsonObject headers = new JsonObject();
    // specify preferred accepted content type, according to https://tools.ietf.org/html/rfc7517#section-8.5
    // there's a specific media type for this resource: application/jwk-set+json but we also allow plain application/json
    headers.put("Accept", "application/jwk-set+json, application/json");

    return fetch(HttpMethod.GET, config.getJwkPath(), headers, null)
      .compose(reply -> {
        if (reply.body() == null || reply.body().length() == 0) {
          return Future.failedFuture("No Body");
        }

        JsonObject json;

        if (reply.is("application/jwk-set+json") || reply.is("application/json")) {
          try {
            json = new JsonObject(reply.body());
          } catch (RuntimeException e) {
            return Future.failedFuture(e);
          }
        } else {
          return Future.failedFuture("Cannot handle content type: " + reply.headers().get("Content-Type"));
        }

        try {
          if (json.containsKey("error")) {
            return Future.failedFuture(extractErrorDescription(json));
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
            return Future.succeededFuture(json);
          }
        } catch (RuntimeException e) {
          return Future.failedFuture(e);
        }
      });
  }

  /**
   * The client sends the end-user's browser to this endpoint to request their authentication and consent. This endpoint is used in the code and implicit OAuth 2.0 flows which require end-user interaction.
   * <p>
   * see: https://tools.ietf.org/html/rfc6749
   */
  public String authorizeURL(JsonObject params) {
    final JsonObject query = params.copy();

    final OAuth2FlowType flow;
    if (params.getString("flow") != null && !params.getString("flow").isEmpty()) {
      flow = OAuth2FlowType.getFlow(params.getString("flow"));
    } else {
      flow = config.getFlow();
    }

    if (flow != OAuth2FlowType.AUTH_CODE) {
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
      if (config.getClientAssertionType() != null) {
        query
          .put("client_assertion_type", config.getClientAssertionType());
      }
      if (config.getClientAssertion() != null) {
        query
          .put("client_assertion", config.getClientAssertion());
      }
    }

    final String path = config.getAuthorizationPath();
    final String url = path.charAt(0) == '/' ? config.getSite() + path : path;

    return url + '?' + SimpleHttpClient.jsonToQuery(query);
  }

  /**
   * Post an OAuth 2.0 grant (code, refresh token, resource owner password credentials, client credentials) to obtain an ID and / or access token.
   * <p>
   * see: https://tools.ietf.org/html/rfc6749
   */
  public Future<JsonObject> token(String grantType, JsonObject params) {
    // quick check and abort
    if (grantType == null) {
      return Future.failedFuture("Token request requires a grantType other than null");
    }

    final JsonObject headers = new JsonObject();

    final boolean confidentialClient = config.getClientId() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientId() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + base64Encode(basic.getBytes(StandardCharsets.UTF_8)));
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
        if (config.getClientAssertionType() != null) {
          form
            .put("client_assertion_type", config.getClientAssertionType());
        }
        if (config.getClientAssertion() != null) {
          form
            .put("client_assertion", config.getClientAssertion());
        }
      }
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = SimpleHttpClient.jsonToQuery(form);

    // specify preferred accepted content type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    return fetch(HttpMethod.POST, config.getTokenPath(), headers, payload)
      .compose(reply -> {
        if (reply.body() == null || reply.body().length() == 0) {
          return Future.failedFuture("No Body");
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = reply.jsonObject();
          } catch (RuntimeException e) {
            return Future.failedFuture(e);
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            json = SimpleHttpClient.queryToJson(reply.body());
          } catch (UnsupportedEncodingException | RuntimeException e) {
            return Future.failedFuture(e);
          }
        } else {
          return Future.failedFuture("Cannot handle content type: " + reply.headers().get("Content-Type"));
        }

        try {
          if (json == null || json.containsKey("error")) {
            return Future.failedFuture(extractErrorDescription(json));
          } else {
            OAuth2API.processNonStandardHeaders(json, reply, config.getScopeSeparator());
            return Future.succeededFuture(json);
          }
        } catch (RuntimeException e) {
          return Future.failedFuture(e);
        }
      });
  }

  /**
   * Validate an access token and retrieve its underlying authorisation (for resource servers).
   * <p>
   * see: https://tools.ietf.org/html/rfc7662
   */
  public Future<JsonObject> tokenIntrospection(String tokenType, String token) {
    final JsonObject headers = new JsonObject();

    final boolean confidentialClient = config.getClientId() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientId() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + base64Encode(basic.getBytes(StandardCharsets.UTF_8)));
    }

    final JsonObject form = new JsonObject()
      .put("token", token)
      // optional param from RFC7662
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = SimpleHttpClient.jsonToQuery(form);
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    return fetch(HttpMethod.POST, config.getIntrospectionPath(), headers, payload)
      .compose(reply -> {
        if (reply.body() == null || reply.body().length() == 0) {
          return Future.failedFuture("No Body");
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = reply.jsonObject();
          } catch (RuntimeException e) {
            return Future.failedFuture(e);
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            json = SimpleHttpClient.queryToJson(reply.body());
          } catch (UnsupportedEncodingException | RuntimeException e) {
            return Future.failedFuture(e);
          }
        } else {
          return Future.failedFuture("Cannot handle accessToken type: " + reply.headers().get("Content-Type"));
        }

        try {
          if (json == null || json.containsKey("error")) {
            return Future.failedFuture(extractErrorDescription(json));
          } else {
            processNonStandardHeaders(json, reply, config.getScopeSeparator());
            return Future.succeededFuture(json);
          }
        } catch (RuntimeException e) {
          return Future.failedFuture(e);
        }
      });
  }

  /**
   * Revoke an obtained access or refresh token.
   * <p>
   * see: https://tools.ietf.org/html/rfc7009
   */
  public Future<Void> tokenRevocation(String tokenType, String token) {
    if (token == null) {
      return Future.failedFuture("Cannot revoke null token");
    }

    final JsonObject headers = new JsonObject();

    final boolean confidentialClient = config.getClientId() != null && config.getClientSecret() != null;

    if (confidentialClient) {
      String basic = config.getClientId() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + base64Encode(basic.getBytes(StandardCharsets.UTF_8)));
    }

    final JsonObject form = new JsonObject();

    form
      .put("token", token)
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = SimpleHttpClient.jsonToQuery(form);
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    return fetch(HttpMethod.POST, config.getRevocationPath(), headers, payload)
      .compose(reply -> {
        if (reply.body() == null) {
          return Future.failedFuture("No Body");
        }

        return Future.succeededFuture();
      });
  }

  /**
   * Retrieve profile information and other attributes for a logged-in end-user.
   * <p>
   * see: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
   */
  public Future<JsonObject> userInfo(String accessToken, JWT jwt) {
    final JsonObject headers = new JsonObject();
    final JsonObject extraParams = config.getUserInfoParameters();
    String path = config.getUserInfoPath();

    if (path == null) {
      return Future.failedFuture("userInfo path is not configured");
    }

    if (extraParams != null) {
      path += "?" + SimpleHttpClient.jsonToQuery(extraParams);
    }

    headers.put("Authorization", "Bearer " + accessToken);
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/jwt,application/x-www-form-urlencoded;q=0.9");

    return fetch(HttpMethod.GET, path, headers, null)
      .compose(reply -> {
        Buffer body = reply.body();

        if (body == null) {
          return Future.failedFuture("No Body");
        }

        // userInfo is expected to be an object
        JsonObject userInfo;

        if (reply.is("application/json")) {
          try {
            // userInfo is expected to be an object
            userInfo = reply.jsonObject();
          } catch (RuntimeException e) {
            return Future.failedFuture(e);
          }
        } else if (reply.is("application/jwt")) {
          try {
            // userInfo is expected to be a JWT
            userInfo = jwt.decode(body.toString(StandardCharsets.UTF_8));
          } catch (RuntimeException e) {
            return Future.failedFuture(e);
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            // attempt to convert url encoded string to json
            userInfo = SimpleHttpClient.queryToJson(reply.body());
          } catch (RuntimeException | UnsupportedEncodingException e) {
            return Future.failedFuture(e);
          }
        } else {
          return Future.failedFuture("Cannot handle Content-Type: " + reply.headers().get("Content-Type"));
        }

        processNonStandardHeaders(userInfo, reply, config.getScopeSeparator());
        return Future.succeededFuture(userInfo);
      });
  }

  /**
   * The logout (end-session) endpoint is specified in OpenID Connect Session Management 1.0.
   * <p>
   * see: https://openid.net/specs/openid-connect-session-1_0.html
   */
  public @Nullable String endSessionURL(String idToken, JsonObject params) {
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

    return url + '?' + SimpleHttpClient.jsonToQuery(query);
  }

  /**
   * Sign out an end-user.
   * <p>
   * see:
   */
  public Future<Void> logout(String accessToken, String refreshToken) {
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

    return fetch(HttpMethod.POST, config.getLogoutPath(), headers, payload)
      .mapEmpty();
  }

  private String extractErrorDescription(JsonObject json) {
    if (json == null) {
      return "null";
    }

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

    if (description == null) {
      return "null";
    }

    return description;
  }

  public Future<SimpleHttpResponse> fetch(HttpMethod method, String path, JsonObject headers, Buffer payload) {

    if (path == null || path.length() == 0) {
      // and this can happen as it is a config option that is dependent on the provider
      return Future.failedFuture("Invalid path");
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
    return makeRequest(options, payload);
  }

  private Future<SimpleHttpResponse> makeRequest(RequestOptions options, Buffer payload) {
    return client.request(options)
      .compose(req -> {

        final Function<HttpClientResponse, Future<SimpleHttpResponse>> resultHandler = res -> {
          // read the body regardless
          return res.body()
            .compose(body -> {
              final SimpleHttpResponse oauth2res = new SimpleHttpResponse(res.statusCode(), res.headers(), body);
              if (res.statusCode() < 200 || res.statusCode() >= 300) {
                if (oauth2res.body() == null || oauth2res.body().length() == 0) {
                  return Future.failedFuture(res.statusMessage());
                } else {
                  if (oauth2res.is("application/json")) {
                    // if value is json, extract error, error_descriptions
                    try {
                      JsonObject error = oauth2res.jsonObject();
                      if (error != null && error.containsKey("error")) {
                        if (error.containsKey("error_description")) {
                          return Future.failedFuture(error.getString("error") + ": " + error.getString("error_description"));
                        } else {
                          return Future.failedFuture(error.getString("error"));
                        }
                      }
                    } catch (RuntimeException e) {
                      // ignore, we can't parse the json, don't mind, rely on the status code anyway
                    }
                  }
                  return Future.failedFuture(res.statusMessage() + ": " + oauth2res.body());
                }
              } else {
                return Future.succeededFuture(oauth2res);
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

  public static void processNonStandardHeaders(JsonObject json, SimpleHttpResponse reply, String sep) {
    // inspect the response headers for the non-standard:
    // X-OAuth-Scopes and X-Accepted-OAuth-Scopes
    final String xOAuthScopes = reply.getHeader("X-OAuth-Scopes");
    final String xAcceptedOAuthScopes = reply.getHeader("X-Accepted-OAuth-Scopes");

    if (xOAuthScopes != null) {
      LOG.trace("Received non-standard X-OAuth-Scopes: " + xOAuthScopes);
      if (json.containsKey("scope")) {
        json.put("scope", json.getString("scope") + sep + xOAuthScopes);
      } else {
        json.put("scope", xOAuthScopes);
      }
    }

    if (xAcceptedOAuthScopes != null) {
      LOG.trace("Received non-standard X-Accepted-OAuth-Scopes: " + xAcceptedOAuthScopes);
      json.put("acceptedScopes", xAcceptedOAuthScopes);
    }
  }

}
