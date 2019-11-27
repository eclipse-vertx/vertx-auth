/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.ldap;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.ldap.LdapAuthentication;
import io.vertx.test.core.VertxTestBase;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.CreateLdapServerRule;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.function.Consumer;

@CreateDS(name = "myDS", partitions = { @CreatePartition(name = "test", suffix = "dc=myorg,dc=com") })
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP", address = "localhost") })
@ApplyLdifFiles({ "ldap.ldif" })
public class LdapAuthenticationTest extends VertxTestBase {
  
  @ClassRule
  public static CreateLdapServerRule serverRule = new CreateLdapServerRule();
  private AuthProvider authProvider;
  
  @Test
  public void testSimpleAuthenticate() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleAuthenticateFailWrongPassword() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "wrongpassword");
    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleAuthenticateFailWrongUser() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "frank").put("password", "sausages");
    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }
/*
  @Test
  public void testHasRole() throws Exception {
    loginThen(user -> this.<Boolean>executeTwice(handler -> user.isAuthorized("role:morris_dancer", handler), res -> {
      assertTrue(res.succeeded());
      assertTrue(res.result());
    }));
    await();
  }

  @Test
  public void testNotHasRole() throws Exception {
    loginThen(user -> this.<Boolean>executeTwice(handler -> user.isAuthorized("role:manager", handler), res -> {
      assertTrue(res.succeeded());
      assertFalse(res.result());
    }));
    await();
  }

  @Test
  public void testHasPermission() throws Exception {
    loginThen(user -> this.<Boolean>executeTwice(handler -> user.isAuthorized("do_actual_work", handler), res -> {
      assertTrue(res.succeeded());
      assertTrue(res.result());
    }));
    await();
  }

  @Test
  public void testNotHasPermission() throws Exception {
    loginThen(user -> this.<Boolean>executeTwice(handler -> user.isAuthorized("play_golf", handler), res -> {
      assertTrue(res.succeeded());
      assertFalse(res.result());
    }));
    await();
  }
*/
  private void loginThen(Consumer<User> runner) throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      runner.accept(user);
    }));
  }

  private <T> void executeTwice(Consumer<Handler<AsyncResult<T>>> action, Consumer<AsyncResult<T>> resultConsumer) {
    action.accept(res -> {
      resultConsumer.accept(res);
      action.accept(res2 -> {
        resultConsumer.accept(res);
        testComplete();
      });
    });
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    LdapAuthenticationOptions ldapOptions = new LdapAuthenticationOptions().setUrl("ldap://localhost:" + serverRule.getLdapServer().getPort())
        .setAuthenticationQuery("uid={0},ou=Users,dc=myorg,dc=com");
    
    authProvider = LdapAuthentication.create(vertx, ldapOptions);
  }
/*
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
*/
}
