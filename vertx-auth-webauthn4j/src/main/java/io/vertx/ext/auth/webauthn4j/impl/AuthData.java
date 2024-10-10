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

package io.vertx.ext.auth.webauthn4j.impl;

/**
 * FIDO2 Authenticator Data
 * This class decodes the buffer into a parsable object
 */
public class AuthData {

  public static final int USER_PRESENT = 0x01;
  public static final int USER_VERIFIED = 0x04;
  public static final int ATTESTATION_DATA = 0x40;
  public static final int EXTENSION_DATA = 0x80;

}
