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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.mongo.HashStrategy.SaltStyle;
import io.vertx.ext.auth.mongo.MongoAuth;

/**
 * Testing MongoAuth setting the salt to a column in the user
 * 
 * @author mremme
 */

public class MongoAuthCOLUMNTest extends MongoAuthNO_SALTTest {

  public MongoAuthCOLUMNTest() {
  }

  @Override
  protected JsonObject createAuthServiceConfig() {
    JsonObject js = new JsonObject();
    js.put(MongoAuth.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuth.DEFAULT_COLLECTION_NAME));
    js.put(MongoAuth.PROPERTY_SALT_STYLE, SaltStyle.COLUMN);
    return js;
  }

  @Override
  protected void initAuthService() throws Exception {
    super.initAuthService();
    assertEquals(SaltStyle.COLUMN, authProvider.getHashStrategy().getSaltStyle());
  }

}
