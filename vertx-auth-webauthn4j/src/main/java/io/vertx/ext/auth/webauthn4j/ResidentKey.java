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
package io.vertx.ext.auth.webauthn4j;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;

/**
 * ResidentKey
 * https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
 *
 * This enum is used to specify the desired behaviour for resident keys with the authenticator.
 */
@VertxGen
public enum ResidentKey {
  DISCOURAGED("discouraged"),
  PREFERRED("preferred"),
  REQUIRED("required");

  private final String value;

  ResidentKey(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return value;
  }

  @Nullable
  @GenIgnore(GenIgnore.PERMITTED_TYPE)
  public static ResidentKey of(String string) {
    for (ResidentKey el : values()) {
      if (el.toString().equals(string)) {
        return el;
      }
    }
    return null;
  }
}
