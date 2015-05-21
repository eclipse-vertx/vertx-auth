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
 * currently allows user/role/permission information to be accessed from simple properties files or LDAP servers.
 *
 * Vert.x auth is also used by vertx-web to handle its authentication and authorisation.
 *
 * == Basic concepts
 *
 * _Authentication_ (aka _log in_) means verifying the identity of a user.
 *
 * _Authorisation_ means verifying a user is allowed to access some resource.
 *
 * The service uses a familiar user/role/permission model that you will probably know already:
 *
 * Users can have zero or more roles, e.g. "manager", "developer".
 *
 * Roles can have zero or more permissions, e.g. a manager might have permission "approve expenses", "conduct_reviews",
 * and a developer might have a permission "commit_code".
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
 * === Re-creating users from Buffers
 *
 * The operation {@link io.vertx.ext.auth.AuthProvider#fromBuffer(io.vertx.core.buffer.Buffer)} allows a User object
 * to be reconstructed from a {@link io.vertx.core.buffer.Buffer}. This is primarily used in vertx-web session clustering
 * to allow the instance to be serialized in the session and passed over the wire to other nodes of the cluster.
 *
 * == Authorisation
 *
 * Once you have an {@link io.vertx.ext.auth.User} instance you can call methods on it to authorise it.
 *
 * To check if a user has a specific role you use {@link io.vertx.ext.auth.User#hasRole},
 * to check if a user has all the specified roles you use {@link io.vertx.ext.auth.User#hasRoles},
 * to check if a user has a specific permission you use {@link io.vertx.ext.auth.User#hasPermission},
 * to check if a user has all the specified permissions you use {@link io.vertx.ext.auth.User#hasPermissions}.
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
 * === Caching roles and permissions
 *
 * The user object will cache any roles and permissions so subsequently calls to check if it has the same roles or
 * permissions will result in the underlying provider being called.
 *
 * In order to clear the internal cache you can use {@link io.vertx.ext.auth.User#clearCache()}.
 *
 * === The User Principal
 *
 * You can get the Principal corresponding to the authenticated user with {@link io.vertx.ext.auth.User#principal()}.
 *
 * What this returns depends on the underlying implementation.
 *
 * === Clusterable users
 *
 * Sometimes users might be put into sessions and clustered to other nodes. For implementations that do not want to
 * be clustered in this way, they should return `false` from this method.
 *
 * == The Apache Shiro implementation
 *
 * This component contains an out of the box implementation that uses http://shiro.apache.org/[Apache Shiro].
 *
 * We provide out of the box support for properties and LDAP based auth using Shiro.
 *
 * To create an instance of the provider you use {@link io.vertx.ext.auth.shiro.ShiroAuth}. You specify the type of
 * Shiro auth provider that you want with {@link io.vertx.ext.auth.shiro.ShiroAuthRealmType}, and you specify the
 * configuration in a JSON object.
 *
 * Here's an example of creating a Shiro auth provider:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example3}
 * ----
 *
 * === The Shiro properties auth provider
 *
 * This auth provider implementation uses Apache Shiro to get user/role/permission information from a properties file.
 *
 * The implementation will, by default, look for a file called `vertx-users.properties` on the classpath.
 *
 * If you want to change this, you can use the `properties_path` configuration element to define how the properties
 * file is found.
 *
 * The default value is `classpath:vertx-users.properties`.
 *
 * If the value is prefixed with `classpath:` then the classpath will be searched for a properties file of that name.
 *
 * If the value is prefixed with `file:` then it specifies a file on the file system.
 *
 * If the value is prefixed with `url:` then it specifies a URL from where to load the properties.
 *
 * The properties file should have the following structure:
 *
 * Each line should either contain the username, password and roles for a user or the permissions in a role.
 *
 * For a user line it should be of the form:
 *
 *  user.{username}={password},{roleName1},{roleName2},...,{roleNameN}
 *
 * For a role line it should be of the form:
 *
 *  role.{roleName}={permissionName1},{permissionName2},...,{permissionNameN}
 *
 * Here's an example:
 * ----
 * user.tim = mypassword,administrator,developer
 * user.bob = hispassword,developer
 * user.joe = anotherpassword,manager
 * role.administrator=*
 * role.manager=play_golf,say_buzzwords
 * role.developer=do_actual_work
 * ----
 *
 * When describing roles a wildcard `*` can be used to indicate that the role has all permissions
 *
 * === The Shiro LDAP auth provider
 *
 * The LDAP auth realm gets user/role/permission information from an LDAP server.
 *
 * The following configuration properties are used to configure the LDAP realm:
 *
 * `ldap-user-dn-template`:: this is used to determine the actual lookup to use when looking up a user with a particular
 * id. An example is `uid={0},ou=users,dc=foo,dc=com` - the element `{0}` is substituted with the user id to create the
 * actual lookup. This setting is mandatory.
 * `ldap_url`:: the url to the LDAP server. The url must start with `ldap://` and a port must be specified.
 * An example is `ldap:://myldapserver.mycompany.com:10389`
 * `ldap-authentication-mechanism`:: TODO
 * `ldap-context-factory-class-name`:: TODO
 * `ldap-pooling-enabled`:: TODO
 * `ldap-referral`:: TODO
 * `ldap-system-username`:: TODO
 * `ldap-system-password`:: TODO
 *
 * == The JWT implementation
 *
 * This component contains an out of the box a JWT implementation.
 *
 * JSON Web Token is a simple way to send information in the clear (usually in a URL) whose contents can be verified to
 * be trusted. JWT are well suited for scenarios as:
 *
 * * In a Single Sign-On scenario where you want a separate authentication server that can then send user information in
 *   a trusted way.
 * * Stateless API servers, very well suited for sinple page applications.
 * * etc...
 *
 * Before deciding on using JWT, it's important to note that JWT does not encrypt the payload, it only signs it. You
 * should not send any secret information using JWT, rather you should send information that is not secret but needs to
 * be verified. For instance, sending a signed user id to indicate the user that should be logged in would work great!
 * Sending a user's password would be very, very bad.
 *
 * Its main advantages are:
 *
 * * It allows you to verify token authenticity.
 * * It has a json body to contain any variable amount of data you want.
 * * It's completely stateless.
 *
 * To create an instance of the provider you use {@link io.vertx.ext.auth.jwt.JWTAuth}. You specify the configuration
 * in a JSON object.
 *
 * Here's an example of creating a JWT auth provider:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example5}
 * ----
 *
 * A typical flow of JWT usage is that in your application you have one end point that issues tokens, this end point
 * should be running in SSL mode, there after you verify the request user, say by its username and password you would
 * do:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example6}
 * ----
 *
 * === The JWT keystore file
 *
 * This auth provider requires a keystore in the classpath or in the filesystem with either a {@link javax.crypto.Mac}
 * or a {@link java.security.Signature} in order to sign and verify the generated tokens.
 *
 * The implementation will, by default, look for the following aliases, however not all are required to be present. As
 * a good practice `HS256` should be present:
 * ----
 * `HS256`:: HMAC using SHA-256 hash algorithm
 * `HS384`:: HMAC using SHA-384 hash algorithm
 * `HS512`:: HMAC using SHA-512 hash algorithm
 * `RS256`:: RSASSA using SHA-256 hash algorithm
 * `RS384`:: RSASSA using SHA-384 hash algorithm
 * `RS512`:: RSASSA using SHA-512 hash algorithm
 * `ES256`:: ECDSA using P-256 curve and SHA-256 hash algorithm
 * `ES384`:: ECDSA using P-384 curve and SHA-384 hash algorithm
 * `ES512`:: ECDSA using P-521 curve and SHA-512 hash algorithm
 * ----
 *
 * When no keystore is provided the implementation falls back in unsecure mode and signatures will not be verified, this
 * is useful for the cases where the payload if signed and or encrypted by external means.
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
 * === Using another Shiro Realm
 *
 * It's also possible to create an auth provider instance using a pre-created Apache Shiro Realm object.
 *
 * This is done as follows:
 *
 * [source,java]
 * ----
 * {@link examples.Examples#example4}
 * ----
 *
 * The implementation currently assumes that user/password based authentication is used.
 *
 *
 *
 *
 *
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@Document(fileName = "index.adoc")
@GenModule(name = "vertx-auth")
package io.vertx.ext.auth;

import io.vertx.codegen.annotations.GenModule;
import io.vertx.docgen.Document;