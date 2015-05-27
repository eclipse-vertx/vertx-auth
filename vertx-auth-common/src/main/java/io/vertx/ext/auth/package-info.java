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
 * = Vert.x Auth - Authentication and Authorisation
 *
 * This Vert.x component provides interfaces for authentication and authorisation that can be used from your Vert.x
 * applications and can be backed by different providers.
 *
 * It also provides an implementation that uses http://shiro.apache.org/[Apache Shiro] out-of-the-box but you can provide
 * your own implementation by implementing the {@link io.vertx.ext.auth.AuthProvider} interface.
 *
 * The Vert.x Apache Shiro implementation
 * currently allows user/permission information to be accessed from simple properties files or LDAP servers.
 *
 * Vert.x auth is also used by vertx-web to handle its authentication and authorisation.
 *
 * == Basic concepts
 *
 * _Authentication_ (aka _log in_) means verifying the identity of a user.
 *
 * _Authorisation_ means verifying a user is allowed to access some resource.
 *
 * The service uses a familiar user/permission model that you will probably know already:
 *
 * Permission is a statement that describes raw functionality in the application and nothing more. Permissions are
 * described as a _opaque_ {@link java.lang.String}, meaning that vert.x makes no assumption on the format of the
 * String.
 *
 * A Permission can be e.g.: "code:push", "code_push", "printers:print:lab1-printer". A common pattern to define these
 * Strings is "&lt;domain&gt;[:&lt;action&gt;[:&lt;instance&gt;]], however the choice is up to the developer.
 *
 * == Authentication
 *
 * To authenticate a user you use {@link io.vertx.ext.auth.AuthProvider#authenticate(io.vertx.core.json.JsonObject, io.vertx.core.Handler)}.
 *
 * The first argument is a JSON object which contains authentication information. What this actually contains depends
 * on the specific implementation; for a simple username/password based authentication it might contain something like:
 *
 * ----
 * {
 *   "username": "tim"
 *   "password": "mypassword"
 * }
 * ----
 *
 * For an implementation based on JWT token or OAuth bearer tokens it might contain the token information.
 *
 * Authentication occurs asynchronously and the result is passed to the user on the result handler that was provided in
 * the call. The async result contains an instance of {@link io.vertx.ext.auth.User} which represents the authenticated
 * user and contains operations which allow the user to be authorised.
 *
 * Here's an example of authenticating a user using a simple username/password implementation:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example1}
 * ----
 *
 * == Authorisation
 *
 * Once you have an {@link io.vertx.ext.auth.User} instance you can call methods on it to authorise it.
 *
 * to check if a user has a specific permission you use {@link io.vertx.ext.auth.User#isPermitted}.
 *
 * The results of all the above are provided asynchronously in the handler.
 *
 * Here's an example of authorising a user:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example2}
 * ----
 *
 * Matching of Permissions has no hard constraints by this module, it is the responsibility of the provider to document
 * the underlying implementation.
 *
 * === Caching permissions
 *
 * The user object will cache any permissions so subsequently calls to check if it has the same permissions will result
 * in the underlying provider being called.
 *
 * In order to clear the internal cache you can use {@link io.vertx.ext.auth.User#clearCache()}.
 *
 * === The User Principal
 *
 * You can get the Principal corresponding to the authenticated user with {@link io.vertx.ext.auth.User#principal()}.
 *
 * What this returns depends on the underlying implementation.
 *
 * == Creating your own auth implementation
 *
 * If you wish to create your own auth provider you should implement the {@link io.vertx.ext.auth.AuthProvider} interface.
 *
 * We provide an abstract implementation of user called {@link io.vertx.ext.auth.AbstractUser} which you can subclass
 * to make your user implementation. This contains the caching logic so you don't have to implement that yourself.
 *
 * If you wish your user objects to be clusterable you should make sure they implement {@link io.vertx.core.shareddata.impl.ClusterSerializable}.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@Document(fileName = "index.adoc")
@GenModule(name = "vertx-auth-common")
package io.vertx.ext.auth;

import io.vertx.codegen.annotations.GenModule;
import io.vertx.docgen.Document;