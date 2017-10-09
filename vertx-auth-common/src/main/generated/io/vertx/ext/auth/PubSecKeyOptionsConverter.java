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

package io.vertx.ext.auth;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter for {@link io.vertx.ext.auth.PubSecKeyOptions}.
 *
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.PubSecKeyOptions} original class using Vert.x codegen.
 */
public class PubSecKeyOptionsConverter {

  public static void fromJson(JsonObject json, PubSecKeyOptions obj) {
    if (json.getValue("publicKey") instanceof String) {
      obj.setPublicKey((String)json.getValue("publicKey"));
    }
    if (json.getValue("secretKey") instanceof String) {
      obj.setSecretKey((String)json.getValue("secretKey"));
    }
    if (json.getValue("type") instanceof String) {
      obj.setType((String)json.getValue("type"));
    }
    if (json.getValue("x509Certificates") instanceof JsonArray) {
      json.getJsonArray("x509Certificates").forEach(item -> {
        if (item instanceof String)
          obj.addX509Certificate((String)item);
      });
    }
  }

  public static void toJson(PubSecKeyOptions obj, JsonObject json) {
    if (obj.getPublicKey() != null) {
      json.put("publicKey", obj.getPublicKey());
    }
    if (obj.getSecretKey() != null) {
      json.put("secretKey", obj.getSecretKey());
    }
    if (obj.getType() != null) {
      json.put("type", obj.getType());
    }
    if (obj.getX509Certificates() != null) {
      JsonArray array = new JsonArray();
      obj.getX509Certificates().forEach(item -> array.add(item));
      json.put("x509Certificates", array);
    }
  }
}