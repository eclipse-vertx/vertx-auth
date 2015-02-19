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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.shiro.PropertiesAuthRealmConstants;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;
import io.vertx.ext.auth.shiro.ShiroAuthService;
import io.vertx.ext.auth.test.AuthServiceTestBase;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class PropertiesAuthServiceTest extends AuthServiceTestBase {

  @Override
  protected void initAuthService() throws Exception {
    initAuthService(-1);
  }

  @Override
  protected void initAuthService(long timeout) throws Exception {
    JsonObject config = getConfig();
    if (timeout == -1) {
      authService = ShiroAuthService.create(vertx, ShiroAuthRealmType.PROPERTIES, config);
    } else {
      authService = ShiroAuthService.create(vertx, ShiroAuthRealmType.PROPERTIES, config, timeout);
    }
  }

  protected JsonObject getConfig() {
    JsonObject config = new JsonObject();
    config.put(PropertiesAuthRealmConstants.PROPERTIES_PROPS_PATH_FIELD, "classpath:test-auth.properties");
    return config;
  }

}
