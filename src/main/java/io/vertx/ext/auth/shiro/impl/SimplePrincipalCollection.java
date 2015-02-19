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

import org.apache.shiro.subject.PrincipalCollection;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Seems kludgy having to do this, but not sure how else to authorise using the Shiro API
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class SimplePrincipalCollection implements PrincipalCollection {

  private final Object principal;

  public SimplePrincipalCollection(Object principal) {
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
