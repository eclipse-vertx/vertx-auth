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

import io.vertx.core.VertxException;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.shiro.ShiroAuthRealm;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroAuthRealmBase implements ShiroAuthRealm {

  private static final Logger log = LoggerFactory.getLogger(ShiroAuthRealmBase.class);

  protected DefaultSecurityManager securityManager;
  protected Realm realm;

  protected ShiroAuthRealmBase() {
  }

  public ShiroAuthRealmBase(Realm realm) {
    this.realm = realm;
    this.securityManager = new DefaultSecurityManager(realm);
  }

  @Override
  public void login(JsonObject principal, JsonObject credentials) {
    SubjectContext subjectContext = new DefaultSubjectContext();
    Subject subject = securityManager.createSubject(subjectContext);
    String username = principal.getString("username");
    String password = credentials.getString("password");
    AuthenticationToken token = new UsernamePasswordToken(username, password);
    try {
      subject.login(token);
    } catch (AuthenticationException e) {
      throw new VertxException(e);
    }
  }


  @Override
  public boolean hasRole(JsonObject principal, String role) {
    SubjectContext subjectContext = new DefaultSubjectContext();
    String username = principal.getString("username");
    PrincipalCollection coll = new SimplePrincipalCollection(username);
    subjectContext.setPrincipals(coll);
    Subject subject = securityManager.createSubject(subjectContext);
    return subject.hasRole(role);
  }

  @Override
  public boolean hasPermission(JsonObject principal, String permission) {
    SubjectContext subjectContext = new DefaultSubjectContext();
    String username = principal.getString("username");
    PrincipalCollection coll = new SimplePrincipalCollection(username);
    subjectContext.setPrincipals(coll);
    Subject subject = securityManager.createSubject(subjectContext);
    try {
      subject.checkPermission(permission);
      return true;
    } catch (AuthorizationException e) {
      return false;
    }
  }

}
