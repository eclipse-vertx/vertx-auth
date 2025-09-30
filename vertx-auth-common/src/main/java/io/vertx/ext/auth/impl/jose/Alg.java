package io.vertx.ext.auth.impl.jose;

import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.concurrent.Callable;

/**
 * JWT alg.
 */
public enum Alg {

  HS256("HmacSHA256", "1.2.840.113549.2.9", null),
  HS384("HmacSHA384", "1.2.840.113549.2.10", null),
  HS512("HmacSHA512", "1.2.840.113549.2.11", null),
  RS1(null, null, null), // ????
  RS256("SHA256withRSA", "1.2.840.113549.1.1.11", () -> Signature.getInstance("SHA256withRSA")),
  RS384("SHA384withRSA", "1.2.840.113549.1.1.12", () -> Signature.getInstance("SHA384withRSA")),
  RS512("SHA512withRSA", "1.2.840.113549.1.1.13", () -> Signature.getInstance("SHA512withRSA")),
  ES256K("SHA256withECDSA", null, () -> Signature.getInstance("SHA256withECDSA")),
  ES256("SHA256withECDSA", "1.2.840.10045.4.3.2", () -> Signature.getInstance("SHA256withECDSA")),
  ES384("SHA384withECDSA", "1.2.840.10045.4.3.3", () -> Signature.getInstance("SHA384withECDSA")),
  ES512("SHA512withECDSA", "1.2.840.10045.4.3.4", () -> Signature.getInstance("SHA512withECDSA")),

  PS256("SHA256withRSAandMGF1", "1.2.840.113549.1.1.10", () -> {
    Signature sig = Signature.getInstance("RSASSA-PSS");
    sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1));
    return sig;
  }),
  PS384("SHA384withRSAandMGF1", "1.2.840.113549.1.1.10", () -> {
    Signature sig = Signature.getInstance("RSASSA-PSS");
    sig.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 384 / 8, 1));
    return sig;
  }),
  PS512("SHA512withRSAandMGF1", "1.2.840.113549.1.1.10 ", () -> {
    Signature sig = Signature.getInstance("RSASSA-PSS");
    sig.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1));
    return sig;
  }),
  EdDSA(null, null, () -> Signature.getInstance("EdDSA")),

  ;

  public final String jce;
  public final String oid;
  public final Callable<Signature> signatureProvider;

  Alg(String jce, String oid, Callable<Signature> signatureProvider) {
    this.jce = jce;
    this.oid = oid;
    this.signatureProvider = signatureProvider;
  }
}
