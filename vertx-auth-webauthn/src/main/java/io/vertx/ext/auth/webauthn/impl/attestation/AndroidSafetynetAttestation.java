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
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;

public class AndroidSafetynetAttestation implements Attestation {

  @Override
  public String fmt() {
    return "android-safetynet";
  }

  @Override
  public boolean verify(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject ctapMakeCredResp, AuthenticatorData authr) throws AttestationException {
    throw new AttestationException("Attestation Not Implemented");
  }
}
