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
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;

import java.nio.charset.StandardCharsets;

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
  private String rolePrefix;

  public ShiroUser(Vertx vertx, org.apache.shiro.mgt.SecurityManager securityManager, Subject subject, String rolePrefix) {
    this.vertx = vertx;
    this.securityManager = securityManager;
    this.rolePrefix = rolePrefix;
    this.subject = subject;
    this.username = subject.getPrincipal().toString();
  }

  public ShiroUser() {
  }

  @Override
  protected void doIsPermitted(String permissionOrRole, Handler<AsyncResult<Boolean>> resultHandler) {
    if (permissionOrRole.startsWith(rolePrefix)) {
      vertx.executeBlocking(fut -> {
        final String role = permissionOrRole.substring(rolePrefix.length());
        // before doing any shiro operations set the context
        SecurityUtils.setSecurityManager(securityManager);
        // proceed
        fut.complete(subject.hasRole(role));
      }, resultHandler);
    } else {
      vertx.executeBlocking(fut -> {
        // before doing any shiro operations set the context
        SecurityUtils.setSecurityManager(securityManager);
        // proceed
        fut.complete(subject.isPermitted(permissionOrRole));
      }, resultHandler);
    }
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

    bytes = rolePrefix.getBytes(StandardCharsets.UTF_8);
    buff.appendInt(bytes.length);
    buff.appendBytes(bytes);
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    pos = super.readFromBuffer(pos, buffer);
    int len = buffer.getInt(pos);
    pos += 4;
    byte[] bytes = buffer.getBytes(pos, pos + len);
    username = new String(bytes, StandardCharsets.UTF_8);
    pos += len;

    len = buffer.getInt(pos);
    pos += 4;
    bytes = buffer.getBytes(pos, pos + len);
    rolePrefix = new String(bytes, StandardCharsets.UTF_8);
    pos += len;

    return pos;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    if (authProvider instanceof ShiroAuthProviderImpl) {
      ShiroAuthProviderImpl shiroAuthProvider = (ShiroAuthProviderImpl)authProvider;
      this.vertx = shiroAuthProvider.getVertx();
      this.securityManager = shiroAuthProvider.getSecurityManager();
      // before doing any shiro operations set the context
      SecurityUtils.setSecurityManager(securityManager);
      // generate the subject back from the provider
      SubjectContext subjectContext = new DefaultSubjectContext();
      PrincipalCollection coll = new SimplePrincipalCollection(username, shiroAuthProvider.getRealmName());
      subjectContext.setPrincipals(coll);
      subject = securityManager.createSubject(subjectContext);
    } else {
      throw new IllegalArgumentException("Not a ShiroAuthProviderImpl");
    }
  }
}
