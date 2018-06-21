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
import io.vertx.ext.auth.shiro.PropertiesProviderConstants;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.ext.auth.shiro.ShiroAuthOptions;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;
import org.junit.Test;

import java.io.File;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class PropertiesShiroAuthProviderTest extends ShiroAuthProviderTestBase {

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = ShiroAuth.create(vertx, new ShiroAuthOptions().setType(ShiroAuthRealmType.PROPERTIES).setConfig(getConfig()));
  }

  protected JsonObject getConfig() {
    JsonObject config = new JsonObject();
    config.put(PropertiesProviderConstants.PROPERTIES_PROPS_PATH_FIELD, "classpath:test-auth.properties");
    return config;
  }

  @Test
  public void testHasWildcardPermission() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "paulo").put("password", "secret");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      // paulo can do anything...
      user.isAuthorized("do_actual_work", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testHasWildcardMatchPermission() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "editor").put("password", "secret");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      // editor can edit any newsletter item...
      user.isAuthorized("newsletter:edit:13", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testResolve() throws Exception {
    ClassLoader loader = PropertiesShiroAuthProviderTest.class.getClassLoader();
    File res = new File(loader.getResource("test-auth.properties").toURI());
    try {
      ShiroAuth.create(vertx,
        new ShiroAuthOptions().setType(
          ShiroAuthRealmType.PROPERTIES
        ).setConfig(
          new JsonObject().put(PropertiesProviderConstants.PROPERTIES_PROPS_PATH_FIELD, res.getName())
        ));
      fail();
    } catch (Exception ignore) {
    }
    assertResolve(res.getParentFile(), res.getName());
    assertResolve(res.getParentFile(), "file:" + res.getName());
    assertResolve(res.getParentFile().getParentFile(), "file:" + res.getParentFile().getName() + File.separatorChar + res.getName());
    assertResolve(res.getParentFile().getParentFile(), "classpath:" + res.getName());
    assertResolve(res.getParentFile().getParentFile(), "url:" + res.toURI().toURL());
  }

  private void assertResolve(File cwd, String path) {
    try {
      System.setProperty("vertx.cwd", cwd.getAbsolutePath());
      ShiroAuth.create(vertx,
        new ShiroAuthOptions().setType(
          ShiroAuthRealmType.PROPERTIES
        ).setConfig(
          new JsonObject().put(PropertiesProviderConstants.PROPERTIES_PROPS_PATH_FIELD, path)
        )
      );
    } finally {
      System.clearProperty("vertx.cwd");
    }
  }
}
