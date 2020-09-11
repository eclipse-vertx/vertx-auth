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
 * UserVerificationRequirement
 * https://www.w3.org/TR/webauthn/#enumdef-userverificationrequirement
 */
@VertxGen
public enum UserVerification {
  REQUIRED("required"),
  PREFERRED("preferred"),
  DISCOURAGED("discouraged");

  private final String value;

  UserVerification(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return value;
  }
}
