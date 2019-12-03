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

package io.vertx.ext.auth.mongo.test;

import io.vertx.ext.auth.mongo.HashSaltStyle;
import io.vertx.ext.auth.mongo.MongoAuth;
import io.vertx.ext.auth.mongo.MongoAuthOptions;
import io.vertx.ext.auth.mongo.MongoAuthOptionsConverter;
import io.vertx.ext.mongo.MongoClient;

/**
 * Testing MongoAuth setting the salt to a column in the user
 *
 * @author mremme
 */

public class MongoAuthCOLUMNWithOptionsTest extends MongoAuthNO_SALTTest {

  public MongoAuthCOLUMNWithOptionsTest() {
  }

  @Override
  protected void initAuthService() throws Exception {
    super.initAuthService();
    assertEquals(HashSaltStyle.COLUMN, authProvider.getHashStrategy().getSaltStyle());
  }

}
