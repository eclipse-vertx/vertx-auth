/*
 * Copyright 2016 Red Hat, Inc.
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
package io.vertx.ext.auth.htdigest;

import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class HtdigestAuthTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  protected HtdigestAuth authProvider;

  @Before
  public void setUp() {
    authProvider = HtdigestAuth.create(rule.vertx());
  }

  @Test
  public void testValidDigestWithQOP(TestContext should) {
    final Async test = should.async();

    HtdigestCredentials authInfo = new HtdigestCredentials()
      .setMethod("GET")
      .setUsername("Mufasa")
      .setRealm("testrealm@host.com")
      .setNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
      .setUri("/dir/index.html")
      .setQop("auth")
      .setNc("00000001")
      .setCnonce("0a4f113b")
      .setResponse("6629fae49393a05397450978507c4ef1");

    authProvider
      .authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testValidDigestWithoutQOP(TestContext should) {
    final Async test = should.async();

    HtdigestCredentials authInfo = new HtdigestCredentials()
      .setMethod("GET")
      .setUsername("Mufasa")
      .setRealm("testrealm@host.com")
      .setNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
      .setUri("/dir/index.html")
      .setNc("00000001")
      .setCnonce("0a4f113b")
      .setResponse("670fd8c2df070c60b045671b8b24ff02");

    authProvider
      .authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }
}
