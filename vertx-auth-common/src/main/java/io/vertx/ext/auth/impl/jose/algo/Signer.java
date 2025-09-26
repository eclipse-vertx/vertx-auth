package io.vertx.ext.auth.impl.jose.algo;

import io.vertx.codegen.annotations.Nullable;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

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

  static @Nullable Signature getSignature(String alg) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    Signature sig;

    switch (alg) {
      case HS256:
      case HS384:
      case HS512:
        return null;
      case ES256:
      case ES256K:
        return Signature.getInstance("SHA256withECDSA");
      case ES384:
        return Signature.getInstance("SHA384withECDSA");
      case ES512:
        return Signature.getInstance("SHA512withECDSA");
      case RS256:
        return Signature.getInstance("SHA256withRSA");
      case RS384:
        return Signature.getInstance("SHA384withRSA");
      case RS512:
        return Signature.getInstance("SHA512withRSA");
      case RS1:
        return Signature.getInstance("SHA1withRSA");
      case PS256:
        sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1));
        return sig;
      case PS384:
        sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 384 / 8, 1));
        return sig;
      case PS512:
        sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1));
        return sig;
      case EdDSA:
        return Signature.getInstance("EdDSA");
      default:
        throw new NoSuchAlgorithmException("");
    }
  }


  byte[] sign(byte[] data) throws GeneralSecurityException;
  boolean verify(byte[] expected, byte[] payload) throws GeneralSecurityException;
}
