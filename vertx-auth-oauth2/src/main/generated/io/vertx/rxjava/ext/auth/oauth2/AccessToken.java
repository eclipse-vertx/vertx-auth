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

package io.vertx.rxjava.ext.auth.oauth2;

import java.util.Map;
import io.vertx.lang.rxjava.InternalHelper;
import rx.Observable;
import io.vertx.rxjava.ext.auth.User;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

/**
 * AccessToken extension to the User interface
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.AccessToken original} non RX-ified interface using Vert.x codegen.
 */

public class AccessToken extends User {

  final io.vertx.ext.auth.oauth2.AccessToken delegate;

  public AccessToken(io.vertx.ext.auth.oauth2.AccessToken delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Check if the access token is expired or not.
   * @return 
   */
  public boolean expired() { 
    boolean ret = this.delegate.expired();
    return ret;
  }

  /**
   * Refresh the access token
   * @param callback - The callback function returning the results.
   * @return 
   */
  public AccessToken refresh(Handler<AsyncResult<Void>> callback) { 
    this.delegate.refresh(callback);
    return this;
  }

  /**
   * Refresh the access token
   * @return 
   */
  public Observable<Void> refreshObservable() { 
    io.vertx.rx.java.ObservableFuture<Void> callback = io.vertx.rx.java.RxHelper.observableFuture();
    refresh(callback.toHandler());
    return callback;
  }

  /**
   * Revoke access or refresh token
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @param callback - The callback function returning the results.
   * @return 
   */
  public AccessToken revoke(String token_type, Handler<AsyncResult<Void>> callback) { 
    this.delegate.revoke(token_type, callback);
    return this;
  }

  /**
   * Revoke access or refresh token
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @return 
   */
  public Observable<Void> revokeObservable(String token_type) { 
    io.vertx.rx.java.ObservableFuture<Void> callback = io.vertx.rx.java.RxHelper.observableFuture();
    revoke(token_type, callback.toHandler());
    return callback;
  }

  /**
   * Revoke refresh token and calls the logout endpoint. This is a openid-connect extension and might not be
   * available on all providers.
   * @param callback - The callback function returning the results.
   * @return 
   */
  public AccessToken logout(Handler<AsyncResult<Void>> callback) { 
    this.delegate.logout(callback);
    return this;
  }

  /**
   * Revoke refresh token and calls the logout endpoint. This is a openid-connect extension and might not be
   * available on all providers.
   * @return 
   */
  public Observable<Void> logoutObservable() { 
    io.vertx.rx.java.ObservableFuture<Void> callback = io.vertx.rx.java.RxHelper.observableFuture();
    logout(callback.toHandler());
    return callback;
  }


  public static AccessToken newInstance(io.vertx.ext.auth.oauth2.AccessToken arg) {
    return arg != null ? new AccessToken(arg) : null;
  }
}
