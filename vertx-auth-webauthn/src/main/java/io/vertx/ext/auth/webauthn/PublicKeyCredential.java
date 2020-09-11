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
package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.VertxGen;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * PublicKeyCredential
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
@VertxGen
public enum PublicKeyCredential {
  ES256(-7),
  ES384(-35),
  ES512(-36),
  PS256(-37),
  PS384(-38),
  PS512(-39),
  RS256(-257),
  RS384(-258),
  RS512(-259),
  RS1(-65535),
  // EdDSA(-8)
  ;

  private final int coseId;

  PublicKeyCredential(int coseId) {
    this.coseId = coseId;
  }

  public static PublicKeyCredential valueOf(int coseId) {
    switch (coseId) {
      case -7:
        return ES256;
      case -35:
        return ES384;
      case -36:
        return ES512;
      case -37:
        return PS256;
      case -38:
        return PS384;
      case -39:
        return PS512;
      case -257:
        return RS256;
      case -258:
        return RS384;
      case -259:
        return RS512;
      case -65535:
        return RS1;
      default:
        throw new IllegalArgumentException("Unknown cose-id: " + coseId);
    }
  }

  public Signature signature() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    Signature sig;
    switch (this) {
      case ES256:
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
      default:
        throw new NoSuchAlgorithmException();
    }
  }
  public int coseId() {
    return coseId;
  }
}
