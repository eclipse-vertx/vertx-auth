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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.SecretOptions;
import io.vertx.ext.jwt.JWTOptions;

import java.util.ArrayList;
import java.util.List;

/**
 * Options describing how an JWT Auth should behave.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class JWTAuthOptions {

  // Defaults
  private static final String PERMISSIONS_CLAIM_KEY = "permissions";
  private static final JWTOptions JWT_OPTIONS = new JWTOptions();

  private String permissionsClaimKey;
  private KeyStoreOptions keyStore;
  private List<PubSecKeyOptions> pubSecKeys;
  private List<SecretOptions> secrets;
  private JWTOptions jwtOptions;
  private List<JsonObject> jwks;

  /**
   * Default constructor
   */
  public JWTAuthOptions() {
    init();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public JWTAuthOptions(JWTAuthOptions other) {
    permissionsClaimKey = other.getPermissionsClaimKey();
    keyStore = other.getKeyStore();
    pubSecKeys = other.getPubSecKeys();
    secrets = other.getSecrets();
    jwtOptions = other.getJWTOptions();
    jwks = other.getJwks();
  }

  private void init() {
    permissionsClaimKey = PERMISSIONS_CLAIM_KEY;
    jwtOptions = JWT_OPTIONS;
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public JWTAuthOptions(JsonObject json) {
    init();
    JWTAuthOptionsConverter.fromJson(json, this);
  }


  public String getPermissionsClaimKey() {
    return permissionsClaimKey;
  }

  public JWTAuthOptions setPermissionsClaimKey(String permissionsClaimKey) {
    this.permissionsClaimKey = permissionsClaimKey;
    return this;
  }

  public KeyStoreOptions getKeyStore() {
    return keyStore;
  }

  public JWTAuthOptions setKeyStore(KeyStoreOptions keyStore) {
    this.keyStore = keyStore;
    return this;
  }

  public List<PubSecKeyOptions> getPubSecKeys() {
    return pubSecKeys;
  }

  public JWTAuthOptions setPubSecKeys(List<PubSecKeyOptions> pubSecKeys) {
    this.pubSecKeys = pubSecKeys;
    return this;
  }

  @Deprecated
  public List<SecretOptions> getSecrets() {
    return secrets;
  }

  @Deprecated
  public JWTAuthOptions setSecrets(List<SecretOptions> secrets) {
    this.secrets = secrets;
    return this;
  }

  @Deprecated
  public JWTAuthOptions addSecret(SecretOptions secret) {
    if (this.secrets == null) {
      this.secrets = new ArrayList<>();
    }
    this.secrets.add(secret);
    return this;
  }

  public JWTAuthOptions addPubSecKey(PubSecKeyOptions pubSecKey) {
    if (this.pubSecKeys == null) {
      this.pubSecKeys = new ArrayList<>();
    }
    this.pubSecKeys.add(pubSecKey);
    return this;
  }

  public JWTOptions getJWTOptions() {
    return jwtOptions;
  }

  public JWTAuthOptions setJWTOptions(JWTOptions jwtOptions) {
    this.jwtOptions = jwtOptions;
    return this;
  }

  public List<JsonObject> getJwks() {
    return jwks;
  }

  public JWTAuthOptions setJwks(List<JsonObject> jwks) {
    this.jwks = jwks;
    return this;
  }

  public JWTAuthOptions addJwk(JsonObject jwk) {
    if (this.jwks == null) {
      this.jwks = new ArrayList<>();
    }

    this.jwks.add(jwk);
    return this;
  }
}
