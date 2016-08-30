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

package io.vertx.groovy.ext.auth.oauth2;

import groovy.transform.CompileStatic
import io.vertx.lang.groovy.InternalHelper
import io.vertx.core.json.JsonObject
import java.util.Set
import io.vertx.core.json.JsonObject

/**
 * Helper class for processing Keycloak principal.
 */
@CompileStatic
public class KeycloakHelper {
  private final def io.vertx.ext.auth.oauth2.KeycloakHelper delegate;

  public KeycloakHelper(Object delegate) {
    this.delegate = (io.vertx.ext.auth.oauth2.KeycloakHelper) delegate;
  }

  public Object getDelegate() {
    return delegate;
  }
  /**
   * Get raw `id_token` string from the principal.
   * @param principal user principal
   * @return the raw id token string
   */
  public static String rawIdToken(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.rawIdToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }
  /**
   * Get decoded `id_token` from the principal.
   * @param principal user principal
   * @return the id token
   */
  public static Map<String, Object> idToken(Map<String, Object> principal) {
    def ret = (Map<String, Object>) InternalHelper.wrapObject(io.vertx.ext.auth.oauth2.KeycloakHelper.idToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null));
    return ret;
  }
  /**
   * Get raw `access_token` string from the principal.
   * @param principal user principal
   * @return the raw access token string
   */
  public static String rawAccessToken(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.rawAccessToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }
  /**
   * Get decoded `access_token` from the principal.
   * @param principal user principal
   * @return the access token
   */
  public static Map<String, Object> accessToken(Map<String, Object> principal) {
    def ret = (Map<String, Object>) InternalHelper.wrapObject(io.vertx.ext.auth.oauth2.KeycloakHelper.accessToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null));
    return ret;
  }

  public static int authTime(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.authTime(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String sessionState(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.sessionState(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String acr(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.acr(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String name(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.name(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String email(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.email(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String preferredUsername(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.preferredUsername(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String nickName(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.nickName(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static Set<String> allowedOrigins(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.allowedOrigins(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }
  /**
   * Parse the token string with base64 decoder.
   * This will only obtain the "payload" part of the token.
   * @param token token string
   * @return token payload json object
   */
  public static Map<String, Object> parseToken(String token) {
    def ret = (Map<String, Object>) InternalHelper.wrapObject(io.vertx.ext.auth.oauth2.KeycloakHelper.parseToken(token));
    return ret;
  }
}
