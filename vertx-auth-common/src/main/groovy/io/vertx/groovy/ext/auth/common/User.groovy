/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.vertx.groovy.ext.auth.common;
import groovy.transform.CompileStatic
import io.vertx.core.AsyncResult
import io.vertx.core.Handler
/**
 * Represents an authenticate User and contains operations to authorise the user, using a role/permission
 * based model.
 * <p>
 * Please consult the documentation for a detailed explanation.
*/
@CompileStatic
public class User {
  final def io.vertx.ext.auth.User delegate;
  public User(io.vertx.ext.auth.User delegate) {
    this.delegate = delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  /**
   * Does the user have the specified permission?
   * @param permission the permission
   * @param resultHandler handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have the permission or `false` otherwise.
   * @return the User to enable fluent use
   */
  public User hasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.isAuthorised(permission, resultHandler);
    return this;
  }
  /**
   * The User object will cache any roles or permissions that it knows it has to avoid hitting the
   * underlying auth provider each time.  Use this method if you want to clear this cache.
   * @return the User to enable fluent use
   */
  public User clearCache() {
    this.delegate.clearCache();
    return this;
  }
  /**
   * Get the underlying principal for the User. What this actually returns depends on the implementation.
   * For a simple user/password based auth, it's likely to contain a JSON object with the following structure:
   * <pre>
   *   {
   *     "username", "tim"
   *   }
   * </pre>
   * @return 
   */
  public Map<String, Object> principal() {
    def ret = this.delegate.principal()?.getMap();
    return ret;
  }
  /**
   * Set the auth provider for the User. This is typically used to reattach a detached User with an AuthProvider, e.g.
   * after it has been deserialized.
   * @param authProvider the AuthProvider - this must be the same type of AuthProvider that originally created the User
   */
  public void setAuthProvider(AuthProvider authProvider) {
    this.delegate.setAuthProvider((io.vertx.ext.auth.AuthProvider)authProvider.getDelegate());
  }
}
