/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.mongo;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.mongo.impl.MongoAuthorizationImpl;
import io.vertx.ext.mongo.MongoClient;

/**
 * An extension of AuthProvider which is using {@link MongoClient} as store
 *
 * @author francoisprunier
 */
@VertxGen
public interface MongoAuthorization extends AuthorizationProvider {

  /**
   * The default name of the collection to be used to store user permissions and roles
   */
  String DEFAULT_COLLECTION_NAME = "authorizations";

  /**
   * The default name of the property for the username, like it is stored in mongodb
   */
  String DEFAULT_USERNAME_FIELD = "username";

  /**
   * The default name of the property for the roles, like it is stored in mongodb. Roles are expected to be saved as
   * JsonArray
   */
  String DEFAULT_ROLE_FIELD = "roles";

  /**
   * The default name of the property for the permissions, like it is stored in mongodb. Permissions are expected to be
   * saved as JsonArray
   */
  String DEFAULT_PERMISSION_FIELD = "permissions";

  /**
   * The default value of enablement of the behavior consisting in reading role definitions from another collection to get permissions attached to roles.
   */
  boolean DEFAULT_READ_ROLE_PERMISSIONS = false;

  /**
   * The default name of the collection to be used to store role definitions
   */
  String DEFAULT_ROLES_COLLECTION_NAME = "roles";

  /**
   * The default name of the property for the role name, like it is stored in mongodb
   */
  String DEFAULT_ROLENAME_FIELD = "rolename";

  /**
   * The default name of the property for role permissions, like it is stored in mongodb. Permissions are expected to be
   * saved as JsonArray
   */
  String DEFAULT_ROLE_PERMISSION_FIELD = "permissions";

  /**
   * Creates an instance of MongoAuthorization by using the given {@link MongoClient} and configuration object.
   *
   * @param providerId
   *          the provider ID to differentiate from others
   * @param mongoClient
   *          an instance of {@link MongoClient} to be used for data storage and retrival
   * @param options
   *          the configuration object for the current instance.
   * @return the created instance of {@link MongoAuthorization}
   */
  static MongoAuthorization create(String providerId, MongoClient mongoClient, MongoAuthorizationOptions options) {
    return new MongoAuthorizationImpl(providerId, mongoClient, options);
  }

}
