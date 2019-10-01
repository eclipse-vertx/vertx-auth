package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;

public class AndroidSafetynetAttestation implements Attestation {

  @Override
  public String fmt() {
    return "android-safetynet";
  }

  @Override
  public boolean verify(JsonObject webAuthnResponse, JsonObject ctapMakeCredResp, AuthenticatorData authr) throws AttestationException {
    throw new AttestationException("Attestation Not Implemented");
  }
}
