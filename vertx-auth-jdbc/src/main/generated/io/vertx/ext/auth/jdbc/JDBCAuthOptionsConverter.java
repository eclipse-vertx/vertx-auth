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

package io.vertx.ext.auth.jdbc;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter for {@link io.vertx.ext.auth.jdbc.JDBCAuthOptions}.
 *
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jdbc.JDBCAuthOptions} original class using Vert.x codegen.
 */
public class JDBCAuthOptionsConverter {

  public static void fromJson(JsonObject json, JDBCAuthOptions obj) {
    if (json.getValue("authenticationQuery") instanceof String) {
      obj.setAuthenticationQuery((String)json.getValue("authenticationQuery"));
    }
    if (json.getValue("config") instanceof JsonObject) {
      obj.setConfig(((JsonObject)json.getValue("config")).copy());
    }
    if (json.getValue("datasourceName") instanceof String) {
      obj.setDatasourceName((String)json.getValue("datasourceName"));
    }
    if (json.getValue("permissionsQuery") instanceof String) {
      obj.setPermissionsQuery((String)json.getValue("permissionsQuery"));
    }
    if (json.getValue("rolesPrefix") instanceof String) {
      obj.setRolesPrefix((String)json.getValue("rolesPrefix"));
    }
    if (json.getValue("rolesQuery") instanceof String) {
      obj.setRolesQuery((String)json.getValue("rolesQuery"));
    }
    if (json.getValue("shared") instanceof Boolean) {
      obj.setShared((Boolean)json.getValue("shared"));
    }
  }

  public static void toJson(JDBCAuthOptions obj, JsonObject json) {
    if (obj.getAuthenticationQuery() != null) {
      json.put("authenticationQuery", obj.getAuthenticationQuery());
    }
    if (obj.getConfig() != null) {
      json.put("config", obj.getConfig());
    }
    if (obj.getDatasourceName() != null) {
      json.put("datasourceName", obj.getDatasourceName());
    }
    if (obj.getPermissionsQuery() != null) {
      json.put("permissionsQuery", obj.getPermissionsQuery());
    }
    if (obj.getRolesPrefix() != null) {
      json.put("rolesPrefix", obj.getRolesPrefix());
    }
    if (obj.getRolesQuery() != null) {
      json.put("rolesQuery", obj.getRolesQuery());
    }
    json.put("shared", obj.isShared());
  }
}