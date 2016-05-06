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

package io.vertx.rxjava.ext.auth.mongo;

import java.util.Map;
import rx.Observable;
import java.util.List;
import io.vertx.rxjava.ext.mongo.MongoClient;
import io.vertx.core.json.JsonObject;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.rxjava.ext.auth.AuthProvider;

/**
 * An extension of AuthProvider which is using  as store
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.mongo.MongoAuth original} non RX-ified interface using Vert.x codegen.
 */

public class MongoAuth extends AuthProvider {

  final io.vertx.ext.auth.mongo.MongoAuth delegate;

  public MongoAuth(io.vertx.ext.auth.mongo.MongoAuth delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Creates an instance of MongoAuth by using the given  and configuration object. An example for a
   * configuration object:
   * 
   * <pre>
   * JsonObject js = new JsonObject();
   * js.put(MongoAuth.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuth.DEFAULT_COLLECTION_NAME));
   * </pre>
   * @param mongoClient an instance of  to be used for data storage and retrival
   * @param config the configuration object for the current instance. By this
   * @return the created instance of {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}s
   */
  public static MongoAuth create(MongoClient mongoClient, JsonObject config) { 
    MongoAuth ret = MongoAuth.newInstance(io.vertx.ext.auth.mongo.MongoAuth.create((io.vertx.ext.mongo.MongoClient)mongoClient.getDelegate(), config));
    return ret;
  }

  /**
   * Set the name of the collection to be used. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @param collectionName the name of the collection to be used for storing and reading user data
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setCollectionName(String collectionName) { 
    delegate.setCollectionName(collectionName);
    return this;
  }

  /**
   * Set the name of the field to be used for the username. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @param fieldName the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setUsernameField(String fieldName) { 
    delegate.setUsernameField(fieldName);
    return this;
  }

  /**
   * Set the name of the field to be used for the password Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @param fieldName the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setPasswordField(String fieldName) { 
    delegate.setPasswordField(fieldName);
    return this;
  }

  /**
   * Set the name of the field to be used for the roles. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}. Roles are expected to
   * be saved as JsonArray
   * @param fieldName the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setRoleField(String fieldName) { 
    delegate.setRoleField(fieldName);
    return this;
  }

  /**
   * Set the name of the field to be used for the permissions. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}.
   * Permissions are expected to be saved as JsonArray
   * @param fieldName the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setPermissionField(String fieldName) { 
    delegate.setPermissionField(fieldName);
    return this;
  }

  /**
   * Set the name of the field to be used as property for the username in the method
   * {@link io.vertx.rxjava.ext.auth.AuthProvider#authenticate}. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @param fieldName the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setUsernameCredentialField(String fieldName) { 
    delegate.setUsernameCredentialField(fieldName);
    return this;
  }

  /**
   * Set the name of the field to be used as property for the password of credentials in the method
   * {@link io.vertx.rxjava.ext.auth.AuthProvider#authenticate}. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @param fieldName the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setPasswordCredentialField(String fieldName) { 
    delegate.setPasswordCredentialField(fieldName);
    return this;
  }

  /**
   * Set the name of the field to be used for the salt. Only used when {@link io.vertx.rxjava.ext.auth.mongo.HashStrategy#setSaltStyle} is
   * set to 
   * @param fieldName the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setSaltField(String fieldName) { 
    delegate.setSaltField(fieldName);
    return this;
  }

  /**
   * The name of the collection used to store User objects inside. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @return the collectionName
   */
  public String getCollectionName() { 
    String ret = delegate.getCollectionName();
    return ret;
  }

  /**
   * Get the name of the field to be used for the username. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @return the usernameField
   */
  public String getUsernameField() { 
    String ret = delegate.getUsernameField();
    return ret;
  }

  /**
   * Get the name of the field to be used for the password Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @return the passwordField
   */
  public String getPasswordField() { 
    String ret = delegate.getPasswordField();
    return ret;
  }

  /**
   * Get the name of the field to be used for the roles. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}. Roles are expected to
   * be saved as JsonArray
   * @return the roleField
   */
  public String getRoleField() { 
    String ret = delegate.getRoleField();
    return ret;
  }

  /**
   * Get the name of the field to be used for the permissions. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}.
   * Permissions are expected to be saved as JsonArray
   * @return the permissionField
   */
  public String getPermissionField() { 
    String ret = delegate.getPermissionField();
    return ret;
  }

  /**
   * Get the name of the field to be used as property for the username in the method
   * {@link io.vertx.rxjava.ext.auth.AuthProvider#authenticate}. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @return the usernameCredentialField
   */
  public String getUsernameCredentialField() { 
    String ret = delegate.getUsernameCredentialField();
    return ret;
  }

  /**
   * Get the name of the field to be used as property for the password of credentials in the method
   * {@link io.vertx.rxjava.ext.auth.AuthProvider#authenticate}. Defaults to {@link io.vertx.rxjava.ext.auth.mongo.MongoAuth}
   * @return the passwordCredentialField
   */
  public String getPasswordCredentialField() { 
    String ret = delegate.getPasswordCredentialField();
    return ret;
  }

  /**
   * Get the name of the field to be used for the salt. Only used when {@link io.vertx.rxjava.ext.auth.mongo.HashStrategy#setSaltStyle} is
   * set to 
   * @return the saltField
   */
  public String getSaltField() { 
    String ret = delegate.getSaltField();
    return ret;
  }

  /**
   * The HashStrategy which is used by the current instance
   * @param hashStrategy the {@link io.vertx.rxjava.ext.auth.mongo.HashStrategy} to be set
   * @return the current instance itself for fluent calls
   */
  public MongoAuth setHashStrategy(HashStrategy hashStrategy) { 
    delegate.setHashStrategy((io.vertx.ext.auth.mongo.HashStrategy)hashStrategy.getDelegate());
    return this;
  }

  /**
   * The HashStrategy which is used by the current instance
   * @return the defined instance of {@link io.vertx.rxjava.ext.auth.mongo.HashStrategy}
   */
  public HashStrategy getHashStrategy() { 
    HashStrategy ret = HashStrategy.newInstance(delegate.getHashStrategy());
    return ret;
  }

  /**
   * Insert a new user into mongo in the convenient way
   * @param username the username to be set
   * @param password the passsword in clear text, will be adapted following the definitions of the defined {@link io.vertx.rxjava.ext.auth.mongo.HashStrategy}
   * @param roles a list of roles to be set
   * @param permissions a list of permissions to be set
   * @param resultHandler the ResultHandler will be provided with the id of the generated record
   */
  public void insertUser(String username, String password, List<String> roles, List<String> permissions, Handler<AsyncResult<String>> resultHandler) { 
    delegate.insertUser(username, password, roles, permissions, new Handler<AsyncResult<java.lang.String>>() {
      public void handle(AsyncResult<java.lang.String> ar) {
        if (ar.succeeded()) {
          resultHandler.handle(io.vertx.core.Future.succeededFuture(ar.result()));
        } else {
          resultHandler.handle(io.vertx.core.Future.failedFuture(ar.cause()));
        }
      }
    });
  }

  /**
   * Insert a new user into mongo in the convenient way
   * @param username the username to be set
   * @param password the passsword in clear text, will be adapted following the definitions of the defined {@link io.vertx.rxjava.ext.auth.mongo.HashStrategy}
   * @param roles a list of roles to be set
   * @param permissions a list of permissions to be set
   * @return 
   */
  public Observable<String> insertUserObservable(String username, String password, List<String> roles, List<String> permissions) { 
    io.vertx.rx.java.ObservableFuture<String> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    insertUser(username, password, roles, permissions, resultHandler.toHandler());
    return resultHandler;
  }


  public static MongoAuth newInstance(io.vertx.ext.auth.mongo.MongoAuth arg) {
    return arg != null ? new MongoAuth(arg) : null;
  }
}
