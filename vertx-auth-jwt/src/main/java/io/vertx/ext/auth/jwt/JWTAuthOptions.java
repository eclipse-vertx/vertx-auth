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
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.JWTOptions;

import java.util.ArrayList;
import java.util.List;

/**
 * Options describing how an JWT Auth should behave.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class JWTAuthOptions {

  // Defaults
  private static final String PERMISSIONS_CLAIM_KEY = "permissions";
  private static final JWTOptions JWT_OPTIONS = new JWTOptions();

  private String permissionsClaimKey;
  private io.vertx.ext.auth.jose.KeyStoreOptions keyStore;
  private List<io.vertx.ext.auth.jose.PubSecKeyOptions> pubSecKeys;
  private io.vertx.ext.auth.jose.JWTOptions jwtOptions;
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
    List<PubSecKeyOptions> pubSecKeys = other.getPubSecKeys();
    if (pubSecKeys != null) {
      this.pubSecKeys = new ArrayList<>();
      this.pubSecKeys.addAll(pubSecKeys);
    }

    permissionsClaimKey = other.getPermissionsClaimKey();
    keyStore = other.getKeyStore();
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

  /**
   * @deprecated AuthN and AuthZ have been split in vert.x 4.0.0 in order to specify where
   * authorization will happen see {@link io.vertx.ext.auth.jwt.authorization.JWTAuthorization}.
   */
  @Deprecated
  public String getPermissionsClaimKey() {
    return permissionsClaimKey;
  }

  /**
   * @deprecated AuthN and AuthZ have been split in vert.x 4.0.0 in order to specify where
   * authorization will happen see {@link io.vertx.ext.auth.jwt.authorization.JWTAuthorization}.
   */
  @Deprecated
  public JWTAuthOptions setPermissionsClaimKey(String permissionsClaimKey) {
    this.permissionsClaimKey = permissionsClaimKey;
    return this;
  }

  public KeyStoreOptions getKeyStore() {
    if (keyStore == null) {
      return null;
    } else if (keyStore instanceof KeyStoreOptions) {
      return (KeyStoreOptions) keyStore;
    } else {
      return new KeyStoreOptions(keyStore.toJson());
    }
  }

  public JWTAuthOptions setKeyStore(KeyStoreOptions keyStore) {
    this.keyStore = keyStore;
    return this;
  }

  @GenIgnore
  public JWTAuthOptions setKeyStore(io.vertx.ext.auth.jose.KeyStoreOptions keyStore) {
    this.keyStore = keyStore;
    return this;
  }

  public List<PubSecKeyOptions> getPubSecKeys() {
    if (pubSecKeys == null) {
      return null;
    } else {
      List<PubSecKeyOptions> list = new ArrayList<>();
      pubSecKeys.forEach(psk -> {
        list.add(new PubSecKeyOptions(psk.toJson()));
      });
      return list;
    }
  }

  public JWTAuthOptions setPubSecKeys(List<PubSecKeyOptions> pubSecKeys) {
    if (pubSecKeys == null) {
      this.pubSecKeys = null;
    } else {
      this.pubSecKeys = new ArrayList<>(pubSecKeys);
    }
    return this;
  }

  public JWTAuthOptions addPubSecKey(PubSecKeyOptions pubSecKey) {
    return addPubSecKey((io.vertx.ext.auth.jose.PubSecKeyOptions) pubSecKey);
  }

  @GenIgnore
  public JWTAuthOptions addPubSecKey(io.vertx.ext.auth.jose.PubSecKeyOptions pubSecKey) {
    if (this.pubSecKeys == null) {
      this.pubSecKeys = new ArrayList<>();
    }
    this.pubSecKeys.add(pubSecKey);
    return this;
  }

  public JWTOptions getJWTOptions() {
    if (jwtOptions == null) {
      return null;
    } else if (jwtOptions instanceof JWTOptions) {
      return (JWTOptions) jwtOptions;
    } else {
      return new JWTOptions(jwtOptions.toJson());
    }
  }

  public JWTAuthOptions setJWTOptions(JWTOptions jwtOptions) {
    this.jwtOptions = jwtOptions;
    return this;
  }

  @GenIgnore
  public JWTAuthOptions setJWTOptions(io.vertx.ext.auth.jose.JWTOptions jwtOptions) {
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
