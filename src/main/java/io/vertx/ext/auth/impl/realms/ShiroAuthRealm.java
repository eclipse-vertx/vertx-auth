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

package io.vertx.ext.auth.impl.realms;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.AuthRealm;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public abstract class ShiroAuthRealm implements AuthRealm {

  private static final Logger log = LoggerFactory.getLogger(ShiroAuthRealm.class);

  protected DefaultSecurityManager securityManager;
  protected Realm realm;
  protected JsonObject config;

  protected ShiroAuthRealm() {
  }

  public ShiroAuthRealm(Realm realm) {
    this.realm = realm;
  }

  @Override
  public boolean login(JsonObject credentials) {
    SubjectContext subjectContext = new DefaultSubjectContext();
    Subject subject = securityManager.createSubject(subjectContext);
    String username = credentials.getString("username");
    String password = credentials.getString("password");
    AuthenticationToken token = new UsernamePasswordToken(username, password);
    try {
      subject.login(token);
      return true;
    } catch (UnknownAccountException | IncorrectCredentialsException | LockedAccountException | ExcessiveAttemptsException e) {
      return false;
    } catch (AuthenticationException ae) {
      // Unexpected exception - log it
      log.error("Unexpected exception when logging in", ae.getCause());
      return false;
    }
  }


  @Override
  public boolean hasRole(String principal, String role) {
    SubjectContext subjectContext = new DefaultSubjectContext();
    PrincipalCollection coll = new MyPrincipalCollection(principal);
    subjectContext.setPrincipals(coll);
    Subject subject = securityManager.createSubject(subjectContext);
    return subject.hasRole(role);
  }

  @Override
  public boolean hasPermission(String principal, String permission) {
    SubjectContext subjectContext = new DefaultSubjectContext();
    PrincipalCollection coll = new MyPrincipalCollection(principal);
    subjectContext.setPrincipals(coll);
    Subject subject = securityManager.createSubject(subjectContext);
    try {
      subject.checkPermission(permission);
      return true;
    } catch (AuthorizationException e) {
      return false;
    }
  }

  // Seems kludgy having to do this, but not sure how else to authorise using the Shiro API
  protected static class MyPrincipalCollection implements PrincipalCollection {

    private final String principal;

    MyPrincipalCollection(String principal) {
      this.principal = principal;
    }

    @Override
    public Object getPrimaryPrincipal() {
      return principal;
    }

    @Override
    public <T> T oneByType(Class<T> type) {
      return null;
    }

    @Override
    public <T> Collection<T> byType(Class<T> type) {
      return null;
    }

    @Override
    public List asList() {
      return Arrays.asList(principal);
    }

    @Override
    public Set asSet() {
      return new HashSet<>(asList());
    }

    @Override
    public Collection fromRealm(String realmName) {
      return null;
    }

    @Override
    public Set<String> getRealmNames() {
      return null;
    }

    @Override
    public boolean isEmpty() {
      return false;
    }

    @Override
    public Iterator iterator() {
      return null;
    }
  }
}
