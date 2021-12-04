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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.mongo.MongoAuthorization;
import io.vertx.ext.auth.mongo.MongoAuthorizationOptions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runners.model.InitializationError;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Testing MongoAuth with no encryption for the user password
 *
 * @author mremme
 */

public class MongoAuthorizationWithRolesTest extends MongoAuthorizationTest {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthorizationWithRolesTest.class);

  protected MongoAuthorization authorizationProvider;

  public MongoAuthorizationWithRolesTest() {
    authorizationOptions = new MongoAuthorizationOptions().setReadRolePermissions(true);
  }

  @Test
  public void testAuthoriseWithRolePermission() {
    // "sudo" permission is defined on "superadmin" role
    // read role permissions is enabled above
    assertTrue(authorizationOptions.isReadRolePermissions());
    // so tim must not have the sudo permission
    JsonObject authInfo = new JsonObject();
    authInfo.put(authenticationOptions.getUsernameField(), "tim").put(authenticationOptions.getPasswordField(), "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, onSuccess(has -> {
        assertTrue(PermissionBasedAuthorization.create("sudo").match(user));
        testComplete();
      }));
    }));
    await();
  }

}
