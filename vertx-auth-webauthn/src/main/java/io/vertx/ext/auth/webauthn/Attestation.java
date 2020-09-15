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

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;

/**
 * AttestationConveyancePreference
 * https://www.w3.org/TR/webauthn/#attestation-convey
 */
@VertxGen
public enum Attestation {
  NONE("none"),
  INDIRECT("indirect"),
  DIRECT("direct");

  private final String value;

  Attestation(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return value;
  }

  @GenIgnore
  public static Attestation of(String string) {
    for (Attestation el : values()) {
      if (el.toString().equals(string)) {
        return el;
      }
    }
    return null;
  }
}
