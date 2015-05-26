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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroUser extends AbstractUser {

  private Vertx vertx;
  private org.apache.shiro.mgt.SecurityManager securityManager;
  private String username;
  private Subject subject;
  private JsonObject principal;

  public ShiroUser(Vertx vertx, org.apache.shiro.mgt.SecurityManager securityManager, String username) {
    this.vertx = vertx;
    this.securityManager = securityManager;
    this.username = username;
    setSubject();
  }

  public ShiroUser() {
  }

  @Override
  protected void doHasRole(String role, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking(fut -> fut.complete(subject.hasRole(role)), resultHandler);
  }

  @Override
  protected void doHasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking(fut -> fut.complete(subject.isPermitted(permission)), resultHandler);
  }

  @Override
  protected void doHasRoles(Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking(fut -> fut.complete(subject.hasAllRoles(roles)), resultHandler);
  }

  @Override
  protected void doHasPermissions(Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking(fut -> fut.complete(subject.isPermittedAll(permissions.toArray(new String[permissions.size()]))),
                          resultHandler);
  }

  @Override
  public JsonObject principal() {
    if (principal == null) {
      principal = new JsonObject().put("username", username);
    }
    return principal;
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    byte[] bytes = username.getBytes(StandardCharsets.UTF_8);
    buff.appendInt(bytes.length).appendBytes(bytes);
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    pos = super.readFromBuffer(pos, buffer);
    int len = buffer.getInt(pos);
    pos += 4;
    byte[] bytes = buffer.getBytes(pos, pos + len);
    pos += len;
    username = new String(bytes, StandardCharsets.UTF_8);
    return pos;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    if (authProvider instanceof ShiroAuthProviderImpl) {
      ShiroAuthProviderImpl shiroAuthProvider = (ShiroAuthProviderImpl)authProvider;
      this.vertx = shiroAuthProvider.getVertx();
      this.securityManager = shiroAuthProvider.getSecurityManager();
      setSubject();
    } else {
      throw new IllegalArgumentException("Not a ShiroAuthProviderImpl");
    }
  }

  private void setSubject() {
    SubjectContext subjectContext = new DefaultSubjectContext();
    PrincipalCollection coll = new SimplePrincipalCollection(username);
    subjectContext.setPrincipals(coll);
    subject = securityManager.createSubject(subjectContext);
  }
}
