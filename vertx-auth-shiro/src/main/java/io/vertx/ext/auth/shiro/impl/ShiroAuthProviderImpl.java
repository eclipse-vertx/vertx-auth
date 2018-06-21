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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.ext.auth.shiro.ShiroAuthOptions;
import org.apache.shiro.SecurityUtils;
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
public class ShiroAuthProviderImpl implements ShiroAuth {

  private Vertx vertx;
  private org.apache.shiro.mgt.SecurityManager securityManager;
  private String rolePrefix = DEFAULT_ROLE_PREFIX;
  private String realmName;

  public static ShiroAuth create(Vertx vertx, ShiroAuthOptions options) {
    Realm realm;
    switch (options.getType()) {
      case PROPERTIES:
        realm = PropertiesAuthProvider.createRealm(options.getConfig());
        break;
      case LDAP:
        realm = LDAPAuthProvider.createRealm(options.getConfig());
        break;
      default:
        throw new IllegalArgumentException("Invalid shiro auth realm type: " + options.getType());
    }
    return new ShiroAuthProviderImpl(vertx, realm);
  }

  public ShiroAuthProviderImpl(Vertx vertx, Realm realm) {
    this.vertx = vertx;
    this.securityManager = new DefaultSecurityManager(realm);
    this.realmName = realm.getName();
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    vertx.executeBlocking(fut -> {
      // before doing any shiro operations set the context
      SecurityUtils.setSecurityManager(securityManager);
      // proceed
      SubjectContext subjectContext = new DefaultSubjectContext();
      Subject subject = securityManager.createSubject(subjectContext);
      String username = authInfo.getString("username");
      String password = authInfo.getString("password");
      AuthenticationToken token = new UsernamePasswordToken(username, password);
      try {
        subject.login(token);
        fut.complete(new ShiroUser(vertx, securityManager, subject, rolePrefix));
      } catch (AuthenticationException e) {
        fut.fail(e);
      }
    }, resultHandler);
  }

  @Override
  public ShiroAuth setRolePrefix(String rolePrefix) {
    this.rolePrefix = rolePrefix;
    return this;
  }


  Vertx getVertx() {
    return vertx;
  }

  org.apache.shiro.mgt.SecurityManager getSecurityManager() {
    return securityManager;
  }

  String getRealmName() {
    return realmName;
  }
}
