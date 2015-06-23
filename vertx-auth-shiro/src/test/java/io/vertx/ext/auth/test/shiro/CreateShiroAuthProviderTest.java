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
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.test.core.VertxTestBase;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Test;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class CreateShiroAuthProviderTest extends VertxTestBase {


  @Test
  public void testCreateWithRealm() {
    Realm realm = new MyShiroRealm();
    AuthProvider authProvider = ShiroAuth.create(vertx, realm);
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  class MyShiroRealm implements Realm {

    @Override
    public String getName() {
      return getClass().getName();
    }

    @Override
    public boolean supports(AuthenticationToken token) {
      return true;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

      return new AuthenticationInfo() {
        @Override
        public PrincipalCollection getPrincipals() {
          return new SimplePrincipalCollection(token.getPrincipal(), getClass().getName());
        }

        @Override
        public Object getCredentials() {
          return token.getCredentials();
        }
      };
    }

  }
}
