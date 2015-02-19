/*
 * Copyright 2014 Red Hat, Inc.
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

package io.vertx.ext.auth;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthServiceVerticle extends AbstractAuthServiceVerticle {

  public static final String AUTH_PROVIDER_CLASS_NAME = "provider_class_name";

  protected AuthService createService() {
    String providerClassName = config().getString(AUTH_PROVIDER_CLASS_NAME);
    if (providerClassName == null) {
      throw new IllegalArgumentException(AUTH_PROVIDER_CLASS_NAME + " must be provided");
    }
    // Create the service object
    return AuthService.createFromClassName(vertx, config(), providerClassName);
  }
}
