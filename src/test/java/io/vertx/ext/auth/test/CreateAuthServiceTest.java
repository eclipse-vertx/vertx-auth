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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthRealm;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.impl.realms.PropertiesAuthRealm;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class CreateAuthServiceTest extends VertxTestBase {

  protected AuthService authService;

  protected JsonObject getConfig() {
    JsonObject config = new JsonObject();
    config.put("properties_path", "classpath:test-auth.properties");
    return config;
  }

  @Test
  public void testCreateWithClassName() {
    String className = PropertiesAuthRealm.class.getName();
    authService = AuthService.createWithRealmClassName(vertx, className, getConfig());
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testCreateWithRealm() {
    AuthRealm realm = new PropertiesAuthRealm();
    authService = AuthService.createWithRealm(vertx, realm, getConfig());
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }
}
