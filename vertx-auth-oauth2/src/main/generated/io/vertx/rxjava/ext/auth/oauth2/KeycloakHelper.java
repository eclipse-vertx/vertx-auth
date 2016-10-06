/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.vertx.rxjava.ext.auth.oauth2;

import java.util.Map;
import rx.Observable;
import java.util.Set;
import io.vertx.core.json.JsonObject;

/**
 * Helper class for processing Keycloak principal.
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.KeycloakHelper original} non RX-ified interface using Vert.x codegen.
 */

public class KeycloakHelper {

  final io.vertx.ext.auth.oauth2.KeycloakHelper delegate;

  public KeycloakHelper(io.vertx.ext.auth.oauth2.KeycloakHelper delegate) {
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Get raw `id_token` string from the principal.
   * @param principal user principal
   * @return the raw id token string
   */
  public static String rawIdToken(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.rawIdToken(principal);
    return ret;
  }

  /**
   * Get decoded `id_token` from the principal.
   * @param principal user principal
   * @return the id token
   */
  public static JsonObject idToken(JsonObject principal) { 
    JsonObject ret = io.vertx.ext.auth.oauth2.KeycloakHelper.idToken(principal);
    return ret;
  }

  /**
   * Get raw `access_token` string from the principal.
   * @param principal user principal
   * @return the raw access token string
   */
  public static String rawAccessToken(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.rawAccessToken(principal);
    return ret;
  }

  /**
   * Get decoded `access_token` from the principal.
   * @param principal user principal
   * @return the access token
   */
  public static JsonObject accessToken(JsonObject principal) { 
    JsonObject ret = io.vertx.ext.auth.oauth2.KeycloakHelper.accessToken(principal);
    return ret;
  }

  public static int authTime(JsonObject principal) { 
    int ret = io.vertx.ext.auth.oauth2.KeycloakHelper.authTime(principal);
    return ret;
  }

  public static String sessionState(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.sessionState(principal);
    return ret;
  }

  public static String acr(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.acr(principal);
    return ret;
  }

  public static String name(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.name(principal);
    return ret;
  }

  public static String email(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.email(principal);
    return ret;
  }

  public static String preferredUsername(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.preferredUsername(principal);
    return ret;
  }

  public static String nickName(JsonObject principal) { 
    String ret = io.vertx.ext.auth.oauth2.KeycloakHelper.nickName(principal);
    return ret;
  }

  public static Set<String> allowedOrigins(JsonObject principal) { 
    Set<String> ret = io.vertx.ext.auth.oauth2.KeycloakHelper.allowedOrigins(principal);
    return ret;
  }

  /**
   * Parse the token string with base64 decoder.
   * This will only obtain the "payload" part of the token.
   * @param token token string
   * @return token payload json object
   */
  public static JsonObject parseToken(String token) { 
    JsonObject ret = io.vertx.ext.auth.oauth2.KeycloakHelper.parseToken(token);
    return ret;
  }


  public static KeycloakHelper newInstance(io.vertx.ext.auth.oauth2.KeycloakHelper arg) {
    return arg != null ? new KeycloakHelper(arg) : null;
  }
}
