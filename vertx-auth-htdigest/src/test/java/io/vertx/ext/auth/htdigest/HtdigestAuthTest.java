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

import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class HtdigestAuthTest extends VertxTestBase {

  protected HtdigestAuth authProvider;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = HtdigestAuth.create(vertx);
  }

  @Test
  public void testValidDigestWithQOP() {
    HtdigestAuthInfo authInfo = new HtdigestAuthInfo()
      .setMethod("GET")
      .setUsername("Mufasa")
      .setRealm("testrealm@host.com")
      .setNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
      .setUri("/dir/index.html")
      .setQop("auth")
      .setNc("00000001")
      .setCnonce("0a4f113b")
      .setResponse("6629fae49393a05397450978507c4ef1");
    
    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testValidDigestWithoutQOP() {
    HtdigestAuthInfo authInfo = new HtdigestAuthInfo()
      .setMethod("GET")
      .setUsername("Mufasa")
      .setRealm("testrealm@host.com")
      .setNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
      .setUri("/dir/index.html")
      .setNc("00000001")
      .setCnonce("0a4f113b")
      .setResponse("670fd8c2df070c60b045671b8b24ff02");
    
    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

}
