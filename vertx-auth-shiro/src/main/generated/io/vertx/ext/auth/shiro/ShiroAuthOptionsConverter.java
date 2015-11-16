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

package io.vertx.ext.auth.shiro;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter for {@link io.vertx.ext.auth.shiro.ShiroAuthOptions}.
 *
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.shiro.ShiroAuthOptions} original class using Vert.x codegen.
 */
public class ShiroAuthOptionsConverter {

  public static void fromJson(JsonObject json, ShiroAuthOptions obj) {
    if (json.getValue("config") instanceof JsonObject) {
      obj.setConfig(((JsonObject)json.getValue("config")).copy());
    }
    if (json.getValue("type") instanceof String) {
      obj.setType(io.vertx.ext.auth.shiro.ShiroAuthRealmType.valueOf((String)json.getValue("type")));
    }
  }

  public static void toJson(ShiroAuthOptions obj, JsonObject json) {
    if (obj.getConfig() != null) {
      json.put("config", obj.getConfig());
    }
    if (obj.getType() != null) {
      json.put("type", obj.getType().name());
    }
  }
}