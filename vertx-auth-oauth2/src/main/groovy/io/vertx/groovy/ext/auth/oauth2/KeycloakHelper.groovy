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
  public static String getRawIdToken(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getRawIdToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }
  /**
   * Get decoded `id_token` from the principal.
   * @param principal user principal
   * @return the id token
   */
  public static Map<String, Object> getIdToken(Map<String, Object> principal) {
    def ret = (Map<String, Object>) InternalHelper.wrapObject(io.vertx.ext.auth.oauth2.KeycloakHelper.getIdToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null));
    return ret;
  }
  /**
   * Get raw `access_token` string from the principal.
   * @param principal user principal
   * @return the raw access token string
   */
  public static String getRawAccessToken(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getRawAccessToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }
  /**
   * Get decoded `access_token` from the principal.
   * @param principal user principal
   * @return the access token
   */
  public static Map<String, Object> getAccessToken(Map<String, Object> principal) {
    def ret = (Map<String, Object>) InternalHelper.wrapObject(io.vertx.ext.auth.oauth2.KeycloakHelper.getAccessToken(principal != null ? new io.vertx.core.json.JsonObject(principal) : null));
    return ret;
  }

  public static int getAuthTime(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getAuthTime(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String getSessionState(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getSessionState(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String getAcr(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getAcr(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String getName(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getName(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String getEmail(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getEmail(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String getPreferredUsername(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getPreferredUsername(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static String getNickName(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getNickName(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }

  public static Set<String> getAllowedOrigins(Map<String, Object> principal) {
    def ret = io.vertx.ext.auth.oauth2.KeycloakHelper.getAllowedOrigins(principal != null ? new io.vertx.core.json.JsonObject(principal) : null);
    return ret;
  }
  /**
   * Parse the token string with base64 encoder.
   * This will only obtain the "payload" part of the token.
   * @param token token string
   * @return token payload json object
   */
  public static Map<String, Object> parseToken(String token) {
    def ret = (Map<String, Object>) InternalHelper.wrapObject(io.vertx.ext.auth.oauth2.KeycloakHelper.parseToken(token));
    return ret;
  }
}
