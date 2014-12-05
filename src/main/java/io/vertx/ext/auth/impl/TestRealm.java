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

package io.vertx.ext.auth.impl;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class TestRealm implements Realm {

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
        return null;
      }

      @Override
      public Object getCredentials() {
        return null;
      }
    };
  }
}
