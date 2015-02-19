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

package io.vertx.ext.auth.test.shiro;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.shiro.ShiroAuthServiceVerticle;

import java.util.concurrent.CountDownLatch;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroAuthServiceVerticleTest extends PropertiesAuthServiceTest {

  @Override
  protected void initAuthService(long timeout) throws Exception {
    JsonObject config = getConfig();
    if (timeout != -1) {
      config.put(ShiroAuthServiceVerticle.REAPER_PERIOD, timeout);
    }
    DeploymentOptions options = new DeploymentOptions().setConfig(config);
    CountDownLatch latch = new CountDownLatch(1);
    vertx.deployVerticle("service:io.vertx:shiro-auth-service", options, onSuccess(id -> {
      authService = AuthService.createEventBusProxy(vertx, "vertx.auth");
      latch.countDown();
    }));
    awaitLatch(latch);
  }
}
