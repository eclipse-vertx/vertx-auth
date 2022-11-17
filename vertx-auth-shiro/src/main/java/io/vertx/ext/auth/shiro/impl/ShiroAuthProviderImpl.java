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

import java.util.Collections;
import java.util.Objects;

import io.vertx.core.*;
import io.vertx.core.impl.VertxInternal;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.GetAuthorizationsHack;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.ext.auth.shiro.ShiroAuthOptions;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@Deprecated
public class ShiroAuthProviderImpl implements ShiroAuth {

  private final Vertx vertx;
  private final org.apache.shiro.mgt.SecurityManager securityManager;
  private final String realmName;

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
  public void authenticate(JsonObject credentials, Handler<AsyncResult<User>> resultHandler) {
    authenticate(credentials)
      .onComplete(resultHandler);
  }

  @Override
  public Future<User> authenticate(JsonObject authInfo) {
    return authenticate(new UsernamePasswordCredentials(authInfo));
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    final UsernamePasswordCredentials authInfo;
    try {
      authInfo = (UsernamePasswordCredentials) credentials;
      authInfo.checkValid(null);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    final Promise<User> promise = ((VertxInternal) vertx).promise();

    vertx.executeBlocking(fut -> {
      // before doing any shiro operations set the context
      SecurityUtils.setSecurityManager(securityManager);
      // proceed
      SubjectContext subjectContext = new DefaultSubjectContext();
      Subject subject = securityManager.createSubject(subjectContext);
      String username = authInfo.getUsername();
      String password = authInfo.getPassword();
      AuthenticationToken token = new UsernamePasswordToken(username, password);
      try {
        subject.login(token);
        fut.complete(createUser(securityManager, subject));
      } catch (AuthenticationException e) {
        fut.fail(e);
      }
    }, promise);

    return promise.future();
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

  private User createUser(org.apache.shiro.mgt.SecurityManager securityManager, Subject subject) {
    Objects.requireNonNull(securityManager);
    Objects.requireNonNull(subject);

    JsonObject principal = new JsonObject().put("username", subject.getPrincipal().toString());
    User result = User.create(principal);
    // metadata "amr"
    result.principal().put("amr", Collections.singletonList("pwd"));

    result.authorizations().add("shiro-authentication", GetAuthorizationsHack.getAuthorizations(securityManager, subject));
    return result;
  }

}
