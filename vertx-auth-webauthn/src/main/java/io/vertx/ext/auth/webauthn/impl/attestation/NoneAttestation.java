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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.AttestationCertificates;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.AuthData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaData;

/**
 * Implementation of the "none" attestation check.
 *
 * This is the most common kind of attestation. User Agents will recommend
 * users to use this, for privacy reasons. Most applications should use it
 * too, as trust should be build on first contact, not on the full hardware
 * check.
 *
 * @author <a href="mailto:pmlopes@gmail.com>Paulo Lopes</a>
 */
public class NoneAttestation implements Attestation {

  @Override
  public String fmt() {
    return "none";
  }

  @Override
  public AttestationCertificates validate(WebAuthnOptions options, MetaData metadata, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException {
    // attStmt must be empty
    if (attestation.containsKey("attStmt") && attestation.getJsonObject("attStmt").size() > 0) {
      throw new AttestationException("attStmt is present!");
    }

    return new AttestationCertificates();
  }
}
