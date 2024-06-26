import io.vertx.ext.auth.webauthn.impl.attestation.*;

module io.vertx.auth.webauthn {

  requires transitive io.vertx.auth.common;
  requires io.vertx.core.logging;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

  exports io.vertx.ext.auth.webauthn;
  exports io.vertx.ext.auth.webauthn.impl to io.vertx.tests;
  exports io.vertx.ext.auth.webauthn.impl.metadata to io.vertx.tests;

  // Consider having this as an official SPI package
  uses Attestation;
  provides Attestation with NoneAttestation, FidoU2fAttestation, PackedAttestation, AndroidKeyAttestation, AndroidSafetynetAttestation, TPMAttestation, AppleAttestation;

}
