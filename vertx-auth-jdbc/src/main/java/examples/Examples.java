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

package examples;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class Examples {


  public void example5(Vertx vertx, JsonObject jdbcClientConfig) {

    JDBCClient jdbcClient = JDBCClient.createShared(vertx, jdbcClientConfig);

    JDBCAuth authProvider = JDBCAuth.create(jdbcClient);
  }

}
