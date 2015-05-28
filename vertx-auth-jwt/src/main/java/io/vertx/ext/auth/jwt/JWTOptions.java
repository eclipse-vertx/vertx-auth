/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.jwt;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.List;

/**
 * Options related to creation of new tokens.
 *
 * If any expiresInMinutes, audience, subject, issuer are not provided, there is no default.
 * The jwt generated won't include those properties in the payload.
 *
 * Generated JWTs will include an iat claim by default unless noTimestamp is specified.
 *
 * @author Paulo Lopes
 */
@DataObject
public class JWTOptions {

  private final JsonObject json;

  public JWTOptions() {
    json = new JsonObject();
  }

  public JWTOptions(JsonObject json) {
    this.json = json.copy();
  }

  public JWTOptions(JWTOptions options) {
    this(options.toJSON());
  }

  public String getAlgorithm() {
    return json.getString("algorithm", "HS256");
  }

  /**
   * The algorithm to use, it should be one of the alias [HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512]
   * @param algorithm alias to keystore MAC/Certificate
   * @return fluent API
   */
  public JWTOptions setAlgorithm(String algorithm) {
    json.put("algorithm", algorithm);
    return this;
  }

  public Long getExpiresInMinutes() {
    return json.getLong("expiresInMinutes");
  }

  /**
   * The expiration time for the token in minutes
   * @param expiresInMinutes time in minutes
   * @return fluent API
   */
  public JWTOptions setExpiresInMinutes(long expiresInMinutes) {
    json.put("expiresInMinutes", expiresInMinutes);
    return this;
  }

  public Long getExpiresInSeconds() {
    return json.getLong("expiresInSeconds");
  }

  /**
   * The expiration time for the token in seconds
   * @param expiresInSeconds time in seconds
   * @return fluent API
   */
  public JWTOptions setExpiresInSeconds(long expiresInSeconds) {
    json.put("expiresInSeconds", expiresInSeconds);
    return this;
  }

  public JsonArray getAudience() {
    return json.getJsonArray("audience");
  }

  /**
   * The target audience of this token
   * @param audience the audience for this token
   * @return fluent API
   */
  public JWTOptions setAudience(List<String> audience) {
    json.put("audience", new JsonArray(audience));
    return this;
  }

  /**
   * The target audience of this token
   * @param audience the audience for this token
   * @return fluent API
   */
  public JWTOptions addAudience(String audience) {
    if (!json.containsKey("audience")) {
      json.put("audience", new JsonArray());
    }

    json.getJsonArray("audience").add(audience);
    return this;
  }

  public String getSubject() {
    return json.getString("subject");
  }

  /**
   * The subject of this token
   * @param subject the subject for this token
   * @return fluent API
   */
  public JWTOptions setSubject(String subject) {
    json.put("subject", subject);
    return this;
  }

  public String getIssuer() {
    return json.getString("issuer");
  }

  /**
   * The issuer of this token
   * @param issuer the subject for this token
   * @return fluent API
   */
  public JWTOptions setIssuer(String issuer) {
    json.put("issuer", issuer);
    return this;
  }

  public boolean getNoTimestamp() {
    return json.getBoolean("noTimestamp");
  }

  /**
   * Disable the generation of issued at claim
   * @param noTimestamp flag to control iat claim
   * @return fluent API
   */
  public JWTOptions setNoTimestamp(boolean noTimestamp) {
    json.put("noTimestamp", noTimestamp);
    return this;
  }

  public JsonObject getHeader() {
    return json.getJsonObject("header");
  }

  public JWTOptions addHeader(String name, String value) {
    if (!json.containsKey("header")) {
      json.put("header", new JsonObject());
    }

    getHeader().put(name, value);
    return this;
  }

  /**
   * The permissions of this token.
   *
   * @param permissions the permissions for this token that will be used for AuthZ
   * @return fluent API
   */
  public JWTOptions setPermissions(List<String> permissions) {
    json.put("permissions", new JsonArray(permissions));
    return this;
  }

  /**
   * Add a permission to this token.
   *
   * @param permission permission for this token that will be used for AuthZ
   * @return fluent API
   */
  public JWTOptions addPermission(String permission) {
    if (!json.containsKey("permissions")) {
      json.put("permissions", new JsonArray());
    }

    json.getJsonArray("permissions").add(permission);
    return this;
  }

  public JsonObject toJSON() {
    return json;
  }
}
