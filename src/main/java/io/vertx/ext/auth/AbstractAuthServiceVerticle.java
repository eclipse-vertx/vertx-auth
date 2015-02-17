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

import io.vertx.core.AbstractVerticle;
import io.vertx.serviceproxy.ProxyHelper;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public abstract class AbstractAuthServiceVerticle extends AbstractVerticle {

  protected AuthService service;

  @Override
  public void start() throws Exception {

    // Create the service object
    service = createService();

    // And register it on the event bus against the configured address
    String address = config().getString("address");
    if (address == null) {
      throw new IllegalStateException("address field must be specified in config for service verticle");
    }
    ProxyHelper.registerService(AuthService.class, vertx, service, address);

    // Start it
    service.start();
  }

  @Override
  public void stop() throws Exception {
    service.stop();
  }

  protected abstract AuthService createService();
}
