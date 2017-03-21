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

/**
 * Options describing how an JWT Auth should behave.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class JWTAuthOptions {

  // Defaults
  private static final String PERMISSIONS_CLAIM_KEY = "permissions";


  private String permissionsClaimKey;
  private JWTKeyStoreOptions keyStore;
  private String publicKey;

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
    publicKey = other.getPublicKey();
  }

  private void init() {
    permissionsClaimKey = PERMISSIONS_CLAIM_KEY;
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

  public JWTKeyStoreOptions getKeyStore() {
    return keyStore;
  }

  public JWTAuthOptions setKeyStore(JWTKeyStoreOptions keyStore) {
    this.keyStore = keyStore;
    return this;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public JWTAuthOptions setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }
}
