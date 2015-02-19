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
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.shiro.impl.SimplePrincipalCollection;
import io.vertx.test.core.VertxTestBase;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;

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

//  @Test
//  public void testCreateWithClassName() {
//    String className = PropertiesAuthRealm.class.getName();
//    JsonObject conf = getConfig();
//    conf.put(AuthService.AUTH_REALM_CLASS_NAME_FIELD, className);
//    authService = AuthService.create(vertx, conf);
//    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
//    authService.login(credentials, onSuccess(res -> {
//      assertEquals("tim", res);
//      testComplete();
//    }));
//    await();
//  }
//
//  @Test
//  public void testCreateWithRealm() {
//    ShiroAuthRealm realm = new PropertiesAuthRealm();
//    authService = AuthService.createWithRealm(vertx, realm, getConfig());
//    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
//    authService.login(credentials, onSuccess(res -> {
//      assertEquals("tim", res);
//      testComplete();
//    }));
//    await();
//  }
//
//  @Test
//  public void testCreateWithShiroRealm() {
//    ShiroAuthRealm realm = AuthRealm.create(new MyShiroRealm());
//    realm.init(new JsonObject());
//    authService = AuthService.createWithRealm(vertx, realm, getConfig());
//    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
//    authService.login(credentials, onSuccess(res -> {
//      assertEquals("tim", res);
//      testComplete();
//    }));
//    await();
//  }

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
          return new SimplePrincipalCollection((String)token.getPrincipal());
        }

        @Override
        public Object getCredentials() {
          return token.getCredentials();
        }
      };
    }
  }
}
