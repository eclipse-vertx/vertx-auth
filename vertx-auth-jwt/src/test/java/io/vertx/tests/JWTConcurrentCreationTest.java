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
package io.vertx.tests;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.VertxOptions;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class JWTConcurrentCreationTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext(new VertxOptions().setEventLoopPoolSize(16));

  @Test
  public void testParallelCreation(TestContext should) {
    final Async test = should.async();
    rule.vertx()
      .deployVerticle(DummyVerticle.class.getName(), new DeploymentOptions().setInstances(512))
      .onFailure(should::fail)
      .onSuccess(id -> test.complete());

  }
}
