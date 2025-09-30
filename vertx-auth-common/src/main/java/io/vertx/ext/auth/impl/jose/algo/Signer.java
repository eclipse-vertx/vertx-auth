package io.vertx.ext.auth.impl.jose.algo;

import java.security.GeneralSecurityException;

public interface Signer {

  String EdDSA = "EdDSA";

  String ES256 = "ES256";
  String ES384 = "ES384";
  String ES512 = "ES512";

  String PS256 = "PS256";
  String PS384 = "PS384";
  String PS512 = "PS512";

  String ES256K = "ES256K";

  String RS256 = "RS256";
  String RS384 = "RS384";
  String RS512 = "RS512";

  String RS1 = "RS1";

  String HS256 = "HS256";
  String HS384 = "HS384";
  String HS512 = "HS512";


  byte[] sign(byte[] data) throws GeneralSecurityException;
  boolean verify(byte[] expected, byte[] payload) throws GeneralSecurityException;
}
