package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;

public class NoneAttestation implements Attestation {

  @Override
  public String fmt() {
    return "none";
  }

  @Override
  public boolean verify(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject ctapMakeCredResp, AuthenticatorData authr) throws AttestationException {
    if ((authr.getFlags() & AuthenticatorData.USER_PRESENT) == 0) {
      throw new AttestationException("User was NOT present during authentication!");
    }

    if (!"00000000–0000–0000–0000–000000000000".equals(authr.getAaguidString())) {
      throw new AttestationException("AAGUID is not 00000000–0000–0000–0000–000000000000!");
    }

    if (ctapMakeCredResp.containsKey("attStmt")) {
      throw new AttestationException("attStmt is present!");
    }

    return true;
  }
}
