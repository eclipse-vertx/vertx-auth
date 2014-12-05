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

package io.vertx.ext.auth.test;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthService;

import java.util.concurrent.CountDownLatch;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthServiceVerticleTest extends AuthServiceTest {

  @Override
  public void setUp() throws Exception {
    super.setUp();
    JsonObject config = new JsonObject();
    DeploymentOptions options = new DeploymentOptions().setConfig(config);
    CountDownLatch latch = new CountDownLatch(1);
    vertx.deployVerticle("service:io.vertx:auth-service", options, onSuccess(id -> {
      authService = AuthService.createEventBusProxy(vertx, "vertx.auth");
      latch.countDown();
    }));
    awaitLatch(latch);
  }
}
