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
  ES256K(-47),
  RS256(-257),
  RS384(-258),
  RS512(-259),
  RS1(-65535),
  EdDSA(-8)
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
      case -47:
        return ES256K;
      case -257:
        return RS256;
      case -258:
        return RS384;
      case -259:
        return RS512;
      case -65535:
        return RS1;
      case -8:
        return EdDSA;
      default:
        throw new IllegalArgumentException("Unknown cose-id: " + coseId);
    }
  }

  public int coseId() {
    return coseId;
  }
}
