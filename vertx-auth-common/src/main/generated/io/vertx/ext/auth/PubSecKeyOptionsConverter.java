/*
 * Copyright (c) 2014 Red Hat, Inc. and others
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
    if (json.getValue("algorithm") instanceof String) {
      obj.setAlgorithm((String)json.getValue("algorithm"));
    }
    if (json.getValue("certificate") instanceof Boolean) {
      obj.setCertificate((Boolean)json.getValue("certificate"));
    }
    if (json.getValue("publicKey") instanceof String) {
      obj.setPublicKey((String)json.getValue("publicKey"));
    }
    if (json.getValue("secretKey") instanceof String) {
      obj.setSecretKey((String)json.getValue("secretKey"));
    }
    if (json.getValue("symmetric") instanceof Boolean) {
      obj.setSymmetric((Boolean)json.getValue("symmetric"));
    }
  }

  public static void toJson(PubSecKeyOptions obj, JsonObject json) {
    if (obj.getAlgorithm() != null) {
      json.put("algorithm", obj.getAlgorithm());
    }
    json.put("certificate", obj.isCertificate());
    if (obj.getPublicKey() != null) {
      json.put("publicKey", obj.getPublicKey());
    }
    if (obj.getSecretKey() != null) {
      json.put("secretKey", obj.getSecretKey());
    }
    json.put("symmetric", obj.isSymmetric());
  }
}