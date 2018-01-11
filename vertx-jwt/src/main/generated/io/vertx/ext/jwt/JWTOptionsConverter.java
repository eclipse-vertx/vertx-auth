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

package io.vertx.ext.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter for {@link io.vertx.ext.jwt.JWTOptions}.
 *
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.jwt.JWTOptions} original class using Vert.x codegen.
 */
public class JWTOptionsConverter {

  public static void fromJson(JsonObject json, JWTOptions obj) {
    if (json.getValue("algorithm") instanceof String) {
      obj.setAlgorithm((String)json.getValue("algorithm"));
    }
    if (json.getValue("audience") instanceof JsonArray) {
      java.util.ArrayList<java.lang.String> list = new java.util.ArrayList<>();
      json.getJsonArray("audience").forEach( item -> {
        if (item instanceof String)
          list.add((String)item);
      });
      obj.setAudience(list);
    }
    if (json.getValue("audiences") instanceof JsonArray) {
      json.getJsonArray("audiences").forEach(item -> {
        if (item instanceof String)
          obj.addAudience((String)item);
      });
    }
    if (json.getValue("expiresInMinutes") instanceof Number) {
      obj.setExpiresInMinutes(((Number)json.getValue("expiresInMinutes")).intValue());
    }
    if (json.getValue("expiresInSeconds") instanceof Number) {
      obj.setExpiresInSeconds(((Number)json.getValue("expiresInSeconds")).intValue());
    }
    if (json.getValue("header") instanceof JsonObject) {
      obj.setHeader(((JsonObject)json.getValue("header")).copy());
    }
    if (json.getValue("ignoreExpiration") instanceof Boolean) {
      obj.setIgnoreExpiration((Boolean)json.getValue("ignoreExpiration"));
    }
    if (json.getValue("issuer") instanceof String) {
      obj.setIssuer((String)json.getValue("issuer"));
    }
    if (json.getValue("leeway") instanceof Number) {
      obj.setLeeway(((Number)json.getValue("leeway")).intValue());
    }
    if (json.getValue("noTimestamp") instanceof Boolean) {
      obj.setNoTimestamp((Boolean)json.getValue("noTimestamp"));
    }
    if (json.getValue("permissions") instanceof JsonArray) {
      json.getJsonArray("permissions").forEach(item -> {
        if (item instanceof String)
          obj.addPermission((String)item);
      });
    }
    if (json.getValue("subject") instanceof String) {
      obj.setSubject((String)json.getValue("subject"));
    }
  }

  public static void toJson(JWTOptions obj, JsonObject json) {
    if (obj.getAlgorithm() != null) {
      json.put("algorithm", obj.getAlgorithm());
    }
    if (obj.getAudience() != null) {
      JsonArray array = new JsonArray();
      obj.getAudience().forEach(item -> array.add(item));
      json.put("audience", array);
    }
    json.put("expiresInSeconds", obj.getExpiresInSeconds());
    if (obj.getHeader() != null) {
      json.put("header", obj.getHeader());
    }
    json.put("ignoreExpiration", obj.isIgnoreExpiration());
    if (obj.getIssuer() != null) {
      json.put("issuer", obj.getIssuer());
    }
    json.put("leeway", obj.getLeeway());
    json.put("noTimestamp", obj.isNoTimestamp());
    if (obj.getPermissions() != null) {
      JsonArray array = new JsonArray();
      obj.getPermissions().forEach(item -> array.add(item));
      json.put("permissions", array);
    }
    if (obj.getSubject() != null) {
      json.put("subject", obj.getSubject());
    }
  }
}