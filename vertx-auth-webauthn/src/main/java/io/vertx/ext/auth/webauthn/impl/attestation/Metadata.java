/*
 * Copyright 2019 Red Hat, Inc.
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
package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.Vertx;
import io.vertx.core.file.FileSystem;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.LocalMap;

/**
 * This class will hold the Fido2 Metadata.
 */
public class Metadata {

  public static final int ALG_KEY_ECC_X962_RAW = 0x0100;
  public static final int ALG_KEY_ECC_X962_DER = 0x0101;
  public static final int ALG_KEY_RSA_2048_RAW = 0x0102;
  public static final int ALG_KEY_RSA_2048_DER = 0x0103;
  public static final int ALG_KEY_COSE = 0x0104;

  public static final int BASIC_FULL = 0x3E07;
  public static final int BASIC_SURROGATE = 0x3E08;
  public static final int BASIC_ECDAA = 0x3E09;

  private final LocalMap<String, JsonObject> store;

  public Metadata(Vertx vertx) {
    store = vertx.sharedData()
      .getLocalMap(Metadata.class.getName());
  }

  public JsonObject getStatement(String aaguid) throws AttestationException {
    // locate a statement
    return store.get(aaguid);
  }

  public Metadata loadMetadata(JsonObject json) {
    String aaguid = json.getString("aaguid");
    if ("fido2".equals(json.getString("protocolFamily"))) {
      if (aaguid == null) {
        throw new IllegalArgumentException("Statement doesn't contain {aaguid}");
      }

      store.put(aaguid, json);
    }
    return this;
  }
}
