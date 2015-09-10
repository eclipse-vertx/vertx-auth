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
 * == JDBC Auth Provider implementation
 *
 * We provide an implementation of {@link io.vertx.ext.auth.AuthProvider} which uses the Vert.x {@link io.vertx.ext.jdbc.JDBCClient}
 * to perform authentication and authorisation against any JDBC compliant database. To use this project,
 * add the following dependency to the _dependencies_ section of your build descriptor:
 *
 * * Maven (in your `pom.xml`):
 *
 * [source,xml,subs="+attributes"]
 * ----
 * <dependency>
 *   <groupId>{maven-groupId}</groupId>
 *   <artifactId>{maven-artifactId}</artifactId>
 *   <version>{maven-version}</version>
 * </dependency>
 * ----
 *
 * * Gradle (in your `build.gradle` file):
 *
 * [source,groovy,subs="+attributes"]
 * ----
 * compile {maven-groupId}:{maven-artifactId}:{maven-version}
 * ----
 *
 * To create an instance you first need an instance of {@link io.vertx.ext.jdbc.JDBCClient}. To learn how to create one
 * of those please consult the documentation for the JDBC client.
 *
 * Once you've got one of those you can create a {@link io.vertx.ext.auth.jdbc.JDBCAuth} instance as follows:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example5}
 * ----
 *
 * Once you've got your instance you can authenticate and authorise with it just like any {@link io.vertx.ext.auth.AuthProvider}.
 *
 * The out of the box config assumes certain queries for authentication and authorisation, these can easily be changed
 * with the operations {@link io.vertx.ext.auth.jdbc.JDBCAuth#setAuthenticationQuery(String)},
 * {@link io.vertx.ext.auth.jdbc.JDBCAuth#setPermissionsQuery(String)} and
 * {@link io.vertx.ext.auth.jdbc.JDBCAuth#setRolesQuery(String)}, if you want to use them with a different
 * database schema.
 *
 * The default implementation assumes that the password is stored in the database as a SHA-512 hash after being
 * concatenated with a salt. It also assumes the salt is stored in the table too.
 *
 * If you want to override this behaviour you can do so by providing an alternative hash strategy and setting it with
 * {@link io.vertx.ext.auth.jdbc.JDBCAuth#setHashStrategy(JDBCHashStrategy)}.
 *
 * WARNING: It is advised to always store your passwords as hashes in your database tables which have been created
 * with a salt which should be stored in the row too. A strong hashing algorithm should be used. It is strongly advised
 * never to store your passwords as plain text.
 *
 * == Authentication
 *
 * When authenticating using this implementation, it assumes `username` and `password` fields are present in the
 * authentication info:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example6}
 * ----
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
 * {@link examples.Examples#example7}
 * ----
 *
 * If validating that a user has a particular _role_ then you should prefix the argument with the role prefix.
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example8}
 * ----
 *
 * The default role prefix is `role:`. You can change this with {@link io.vertx.ext.auth.jdbc.JDBCAuth#setRolePrefix(java.lang.String)}.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@Document(fileName = "index.adoc")
@ModuleGen(name = "vertx-auth-jdbc", groupPackage = "io.vertx")
package io.vertx.ext.auth.jdbc;

import io.vertx.codegen.annotations.ModuleGen;
import io.vertx.docgen.Document;