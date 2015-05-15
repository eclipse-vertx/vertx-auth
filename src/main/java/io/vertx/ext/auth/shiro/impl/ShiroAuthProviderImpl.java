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

package io.vertx.ext.auth.shiro.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.VertxException;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;

/**
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroAuthProviderImpl implements AuthProvider {

  private Vertx vertx;
  private org.apache.shiro.mgt.SecurityManager securityManager;

  public static AuthProvider create(Vertx vertx, ShiroAuthRealmType realmType, JsonObject config) {
    Realm realm;
    switch (realmType) {
      case PROPERTIES:
        realm = PropertiesAuthProvider.createRealm(config);
        break;
      case LDAP:
        realm = LDAPAuthProvider.createRealm(config);
        break;
      default:
        throw new IllegalArgumentException("Invalid shiro auth realm type: " + realmType);
    }
    return new ShiroAuthProviderImpl(vertx, realm);
  }

  public ShiroAuthProviderImpl(Vertx vertx, Realm realm) {
    this.vertx = vertx;
    this.securityManager = new DefaultSecurityManager(realm);
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    vertx.executeBlocking(fut -> {
      SubjectContext subjectContext = new DefaultSubjectContext();
      Subject subject = securityManager.createSubject(subjectContext);
      String username = authInfo.getString("username");
      String password = authInfo.getString("password");
      AuthenticationToken token = new UsernamePasswordToken(username, password);
      try {
        subject.login(token);
      } catch (AuthenticationException e) {
        throw new VertxException(e);
      }
      fut.complete(new ShiroUser(vertx, securityManager, username));
    }, resultHandler);
  }

  @Override
  public User fromBuffer(Buffer buffer) {
    ShiroUser user = new ShiroUser(vertx, securityManager);
    user.readFromBuffer(0, buffer);
    return user;
  }

}
