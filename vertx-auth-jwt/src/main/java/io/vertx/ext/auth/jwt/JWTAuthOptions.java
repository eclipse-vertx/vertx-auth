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
  private static final boolean IGNORE_EXPIRATION = false;


  private String permissionsClaimKey;
  private KeyStoreOptions keyStore;
  private List<PubSecKeyOptions> pubSecKeys;
  private List<String> audience;
  private String issuer;
  private boolean ignoreExpiration;

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
    audience = other.getAudience();
    issuer = other.getIssuer();
    ignoreExpiration = other.isIgnoreExpiration();
  }

  private void init() {
    permissionsClaimKey = PERMISSIONS_CLAIM_KEY;
    ignoreExpiration = IGNORE_EXPIRATION;
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

  public JWTAuthOptions addPubSecKey(PubSecKeyOptions pubSecKey) {
    if (this.pubSecKeys == null) {
      this.pubSecKeys = new ArrayList<>();
    }
    this.pubSecKeys.add(pubSecKey);
    return this;
  }

  public List<String> getAudience() {
    return audience;
  }

  /**
   * Set the audience list
   * @param audience  the audience list
   * @return a reference to this for fluency
   */
  public JWTAuthOptions setAudience(List<String> audience) {
    this.audience = audience;
    return this;
  }

  /**
   * Set the audience list
   * @param audience  the audience list
   * @return a reference to this for fluency
   */
  public JWTAuthOptions addAudience(String audience) {
    if (this.audience == null) {
      this.audience = new ArrayList<>();
    }
    this.audience.add(audience);
    return this;
  }

  public String getIssuer() {
    return issuer;
  }

  /**
   * Set the issuer
   * @param issuer  the issuer
   * @return a reference to this for fluency
   */
  public JWTAuthOptions setIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public boolean isIgnoreExpiration() {
    return ignoreExpiration;
  }

  /**
   * Set whether expiration is ignored
   * @param ignoreExpiration  whether expiration is ignored
   * @return a reference to this for fluency
   */
  public JWTAuthOptions setIgnoreExpiration(boolean ignoreExpiration) {
    this.ignoreExpiration = ignoreExpiration;
    return this;
  }
}
