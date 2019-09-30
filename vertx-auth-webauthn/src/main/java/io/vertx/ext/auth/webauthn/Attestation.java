package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.AttestationException;
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;

public interface Attestation {

  String fmt();

  boolean verify(JsonObject webAuthnResponse, JsonObject ctapMakeCredResp, AuthenticatorData authr) throws AttestationException;
}
