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

package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter for {@link io.vertx.ext.auth.jwt.JWTAuthOptions}.
 *
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTAuthOptions} original class using Vert.x codegen.
 */
public class JWTAuthOptionsConverter {

  public static void fromJson(JsonObject json, JWTAuthOptions obj) {
    if (json.getValue("jwtOptions") instanceof JsonObject) {
      obj.setJWTOptions(new io.vertx.ext.jwt.JWTOptions((JsonObject)json.getValue("jwtOptions")));
    }
    if (json.getValue("keyStore") instanceof JsonObject) {
      obj.setKeyStore(new io.vertx.ext.auth.KeyStoreOptions((JsonObject)json.getValue("keyStore")));
    }
    if (json.getValue("permissionsClaimKey") instanceof String) {
      obj.setPermissionsClaimKey((String)json.getValue("permissionsClaimKey"));
    }
    if (json.getValue("pubSecKeys") instanceof JsonArray) {
      json.getJsonArray("pubSecKeys").forEach(item -> {
        if (item instanceof JsonObject)
          obj.addPubSecKey(new io.vertx.ext.auth.PubSecKeyOptions((JsonObject)item));
      });
    }
    if (json.getValue("secrets") instanceof JsonArray) {
      json.getJsonArray("secrets").forEach(item -> {
        if (item instanceof JsonObject)
          obj.addSecret(new io.vertx.ext.auth.SecretOptions((JsonObject)item));
      });
    }
  }

  public static void toJson(JWTAuthOptions obj, JsonObject json) {
    if (obj.getPermissionsClaimKey() != null) {
      json.put("permissionsClaimKey", obj.getPermissionsClaimKey());
    }
  }
}