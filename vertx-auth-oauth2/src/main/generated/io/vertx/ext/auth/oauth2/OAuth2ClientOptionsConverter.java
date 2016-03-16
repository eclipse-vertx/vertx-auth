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

package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter for {@link io.vertx.ext.auth.oauth2.OAuth2ClientOptions}.
 *
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.OAuth2ClientOptions} original class using Vert.x codegen.
 */
public class OAuth2ClientOptionsConverter {

  public static void fromJson(JsonObject json, OAuth2ClientOptions obj) {
    if (json.getValue("authorizationPath") instanceof String) {
      obj.setAuthorizationPath((String)json.getValue("authorizationPath"));
    }
    if (json.getValue("clientID") instanceof String) {
      obj.setClientID((String)json.getValue("clientID"));
    }
    if (json.getValue("clientSecret") instanceof String) {
      obj.setClientSecret((String)json.getValue("clientSecret"));
    }
    if (json.getValue("clientSecretParameterName") instanceof String) {
      obj.setClientSecretParameterName((String)json.getValue("clientSecretParameterName"));
    }
    if (json.getValue("headers") instanceof JsonObject) {
      obj.setHeaders(((JsonObject)json.getValue("headers")).copy());
    }
    if (json.getValue("jwtToken") instanceof Boolean) {
      obj.setJwtToken((Boolean)json.getValue("jwtToken"));
    }
    if (json.getValue("logoutPath") instanceof String) {
      obj.setLogoutPath((String)json.getValue("logoutPath"));
    }
    if (json.getValue("publicKey") instanceof String) {
      obj.setPublicKey((String)json.getValue("publicKey"));
    }
    if (json.getValue("revocationPath") instanceof String) {
      obj.setRevocationPath((String)json.getValue("revocationPath"));
    }
    if (json.getValue("site") instanceof String) {
      obj.setSite((String)json.getValue("site"));
    }
    if (json.getValue("tokenPath") instanceof String) {
      obj.setTokenPath((String)json.getValue("tokenPath"));
    }
    if (json.getValue("useBasicAuthorizationHeader") instanceof Boolean) {
      obj.setUseBasicAuthorizationHeader((Boolean)json.getValue("useBasicAuthorizationHeader"));
    }
    if (json.getValue("userAgent") instanceof String) {
      obj.setUserAgent((String)json.getValue("userAgent"));
    }
    if (json.getValue("userInfoPath") instanceof String) {
      obj.setUserInfoPath((String)json.getValue("userInfoPath"));
    }
  }

  public static void toJson(OAuth2ClientOptions obj, JsonObject json) {
    if (obj.getAuthorizationPath() != null) {
      json.put("authorizationPath", obj.getAuthorizationPath());
    }
    if (obj.getClientID() != null) {
      json.put("clientID", obj.getClientID());
    }
    if (obj.getClientSecret() != null) {
      json.put("clientSecret", obj.getClientSecret());
    }
    if (obj.getClientSecretParameterName() != null) {
      json.put("clientSecretParameterName", obj.getClientSecretParameterName());
    }
    if (obj.getHeaders() != null) {
      json.put("headers", obj.getHeaders());
    }
    json.put("jwtToken", obj.isJwtToken());
    if (obj.getLogoutPath() != null) {
      json.put("logoutPath", obj.getLogoutPath());
    }
    if (obj.getPublicKey() != null) {
      json.put("publicKey", obj.getPublicKey());
    }
    if (obj.getRevocationPath() != null) {
      json.put("revocationPath", obj.getRevocationPath());
    }
    if (obj.getSite() != null) {
      json.put("site", obj.getSite());
    }
    if (obj.getTokenPath() != null) {
      json.put("tokenPath", obj.getTokenPath());
    }
    json.put("useBasicAuthorizationHeader", obj.isUseBasicAuthorizationHeader());
    if (obj.getUserAgent() != null) {
      json.put("userAgent", obj.getUserAgent());
    }
    if (obj.getUserInfoPath() != null) {
      json.put("userInfoPath", obj.getUserInfoPath());
    }
  }
}