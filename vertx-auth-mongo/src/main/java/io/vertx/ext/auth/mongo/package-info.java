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

/**
 * == Mongo Auth Provider implementation
 *
 * We provide an implementation of {@link io.vertx.ext.auth.AuthProvider} which uses the Vert.x {@link io.vertx.ext.mongo.MongoClient}
 * to perform authentication and authorisation against a MongoDb.
 *
 * To create an instance you first need an instance of {@link io.vertx.ext.mongo.MongoClient}. To learn how to create one
 * of those please consult the documentation for the MongoClient.
 *
 * Once you've got one of those you can create a {@link io.vertx.ext.auth.mongo.MongoAuth} instance as follows:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example1(io.vertx.core.Vertx, io.vertx.core.json.JsonObject)}
 * ----
 * 
 * Once you've got your instance you can authenticate and authorise with it just like any {@link io.vertx.ext.auth.AuthProvider}.
 *
 * The out of the box config assumes the usage of the collection with name "user", the username stored and read by field "username" 
 * some others. You can easily change those defaults with the operations 
 * {@link io.vertx.ext.auth.mongo.MongoAuth#setCollectionName(String)}
 * {@link io.vertx.ext.auth.mongo.MongoAuth#setUsernameField(String)}
 * {@link io.vertx.ext.auth.mongo.MongoAuth#setPasswordField(String)}
 * {@link io.vertx.ext.auth.mongo.MongoAuth#setPermissionField(String)}
 * {@link io.vertx.ext.auth.mongo.MongoAuth#setRoleField(String)}
 * if you want to adapt that to your needs.
 *
 * The default implementation assumes that the password is stored in the database as a SHA-512 hash after being
 * concatenated with a salt. It also assumes the salt is stored in the table too. The field, where the salt is
 * stored can be set by {@link io.vertx.ext.auth.mongo.MongoAuth#setSaltField(String) }, the default is "salt".
 * You are able to change this behaviour by using {@link io.vertx.ext.auth.mongo.HashStrategy#setSaltStyle(HashSaltStyle)}.
 * The HashStrategy you can retrieve by  {@link io.vertx.ext.auth.mongo.MongoAuth#getHashStrategy() }.
 * By using this, you are able to set:
 * {@link io.vertx.ext.auth.mongo.HashSaltStyle#NO_SALT} by which passwords are not crypted and stored
 * in cleartext. ( see the warning below! )
 * {@link io.vertx.ext.auth.mongo.HashSaltStyle#COLUMN}, which will create a salt per user and store this
 * inside the defined column of the user. ( see the warning below! )
 * {@link io.vertx.ext.auth.mongo.HashSaltStyle#EXTERNAL}, which will store only the crypted password in the
 * database and will use a salt from external, which you will have to set by {@link io.vertx.ext.auth.mongo.HashStrategy#setExternalSalt(String)}
 *
 * If you want to override this behaviour you can do so by providing an alternative hash strategy and setting it with
 *  {@link io.vertx.ext.auth.mongo.MongoAuth#setHashStrategy(HashStrategy) }
 *
 * WARNING: It is strongly advised to use the {@link io.vertx.ext.auth.mongo.HashSaltStyle#EXTERNAL} option.
 * The NO_SALT option is existing for development phase only and even the COLUMN option is not recommended, cause
 * salt and password are stored inside the same place!
 * 
 * == Authentication
 *
 * When authenticating using this implementation, it assumes `username` and `password` fields are present in the
 * authentication info:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example2(MongoAuth)}
 * ----
 * You are able to modify the credential fields by using the methods
 * {@link io.vertx.ext.auth.mongo.MongoAuth#setUsernameCredentialField(String) }
 * {@link io.vertx.ext.auth.mongo.MongoAuth#setPasswordCredentialField(String) }
 * 
 * == Authorisation - Permission-Role Model
 *
 * Although Vert.x auth itself does not mandate any specific model of permissions (they are just opaque strings), this
 * implementation assumes a familiar user/role/permission model, where a user can have zero or more roles and a role
 * can have zero or more permissions.
 *
 * If validating if a user has a particular permission simply pass the permission into.
 * {@link io.vertx.ext.auth.User#isAuthorised(java.lang.String, io.vertx.core.Handler)} as follows:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example3(io.vertx.ext.auth.User)}
 * ----
 *
 * If validating that a user has a particular _role_ then you should prefix the argument with the role prefix.
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example4}
 * ----
 *
 *
 * @author mremme
 */
@Document(fileName = "index.adoc")
@ModuleGen(name = "vertx-auth-mongo", groupPackage = "io.vertx")
package io.vertx.ext.auth.mongo;

import io.vertx.codegen.annotations.ModuleGen;
import io.vertx.docgen.Document;

