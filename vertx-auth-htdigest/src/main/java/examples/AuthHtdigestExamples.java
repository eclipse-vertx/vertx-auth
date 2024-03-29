/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package examples;

import io.vertx.core.Vertx;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.htdigest.HtdigestAuth;
import io.vertx.ext.auth.htdigest.HtdigestCredentials;

/**
 * @author Paulo Lopes
 */
public class AuthHtdigestExamples {

  public void example1(Vertx vertx) {
    HtdigestAuth authProvider = HtdigestAuth.create(vertx, ".htdigest");
  }

  public void example2(HtdigestAuth authProvider) {
    Credentials authInfo = new HtdigestCredentials()
      .setUsername("Mufasa")
      .setRealm("testrealm@host.com")
      .setNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
      .setMethod("GET")
      .setUri("/dir/index.html")
      .setResponse("6629fae49393a05397450978507c4ef1");

    authProvider.authenticate(authInfo)
      .onSuccess(user -> System.out.println("User: " + user.principal()))
      .onFailure(err -> {
        // Failed!
      });
  }
}
