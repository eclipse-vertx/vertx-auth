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
 * == The JWT auth provider
 *
 * This component contains an out of the box a JWT implementation. To use this project, add the following
 * dependency to the _dependencies_ section of your build descriptor:
 *
 * * Maven (in your `pom.xml`):
 *
 * [source,xml,subs="+attributes"]
 * ----
 * <dependency>
 *   <groupId>${maven.groupId}</groupId>
 *   <artifactId>${maven.artifactId}</artifactId>
 *   <version>${maven.version}</version>
 * </dependency>
 * ----
 *
 * * Gradle (in your `build.gradle` file):
 *
 * [source,groovy,subs="+attributes"]
 * ----
 * compile '${maven.groupId}:${maven.artifactId}:${maven.version}'
 * ----
 *
 * JSON Web Token is a simple way to send information in the clear (usually in a URL) whose contents can be
 * verified to
 * be trusted. JWT are well suited for scenarios as:
 *
 * * In a Single Sign-On scenario where you want a separate authentication server that can then send user
 * information in a trusted way.
 * * Stateless API servers, very well suited for simple page applications.
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
 * {@link examples.AuthJWTExamples#example6}
 * ----
 *
 * A typical flow of JWT usage is that in your application you have one end point that issues tokens, this end point
 * should be running in SSL mode, there after you verify the request user, say by its username and password you would
 * do:
 *
 * [source,java]
 * ----
 * {@link examples.AuthJWTExamples#example7}
 * ----
 *
 * === The JWT keystore file
 *
 * This auth provider requires a keystore in the classpath or in the filesystem with either a
 * `https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html[javax.crypto.Mac]`
 * or a `https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html[java.security.Signature]` in order to
 * sign and verify the generated tokens.
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
 * === Generate a new Keystore file
 *
 * The only required tool to generate a keystore file is `keytool`, you can now specify which algorithms you need by
 * running:
 *
 * ----
 * keytool -genseckey -keystore keystore.jceks -storetype jceks -storepass secret -keyalg HMacSHA256 -keysize 2048 -alias HS256 -keypass secret
 * keytool -genseckey -keystore keystore.jceks -storetype jceks -storepass secret -keyalg HMacSHA384 -keysize 2048 -alias HS384 -keypass secret
 * keytool -genseckey -keystore keystore.jceks -storetype jceks -storepass secret -keyalg HMacSHA512 -keysize 2048 -alias HS512 -keypass secret
 * keytool -genkey -keystore keystore.jceks -storetype jceks -storepass secret -keyalg RSA -keysize 2048 -alias RS256 -keypass secret -sigalg SHA256withRSA -dname "CN=,OU=,O=,L=,ST=,C=" -validity 360
 * keytool -genkey -keystore keystore.jceks -storetype jceks -storepass secret -keyalg RSA -keysize 2048 -alias RS384 -keypass secret -sigalg SHA384withRSA -dname "CN=,OU=,O=,L=,ST=,C=" -validity 360
 * keytool -genkey -keystore keystore.jceks -storetype jceks -storepass secret -keyalg RSA -keysize 2048 -alias RS512 -keypass secret -sigalg SHA512withRSA -dname "CN=,OU=,O=,L=,ST=,C=" -validity 360
 * keytool -genkeypair -keystore keystore.jceks -storetype jceks -storepass secret -keyalg EC -keysize 256 -alias ES256 -keypass secret -sigalg SHA256withECDSA -dname "CN=,OU=,O=,L=,ST=,C=" -validity 360
 * keytool -genkeypair -keystore keystore.jceks -storetype jceks -storepass secret -keyalg EC -keysize 384 -alias ES384 -keypass secret -sigalg SHA384withECDSA -dname "CN=,OU=,O=,L=,ST=,C=" -validity 360
 * keytool -genkeypair -keystore keystore.jceks -storetype jceks -storepass secret -keyalg EC -keysize 521 -alias ES512 -keypass secret -sigalg SHA512withECDSA -dname "CN=,OU=,O=,L=,ST=,C=" -validity 360
 * ----
 *
 * === Read only tokens
 *
 * If you need to consume JWT tokens issues by third parties you probably won't have the private key with you, in that
 * case all you need to have is a public key im PEM format.
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthJWTExamples#example8}
 * ----
 *
 * == AuthN/AuthZ with JWT
 *
 * A common scenario when developing for example micro services is that you want you application to consume APIs. These
 * api's are not meant to be consumed by humans so we should remove all the interactive part of authenticating the
 * consumer out of the picture.
 *
 * In this scenario one can use HTTP as the protocol to consume this API and the HTTP protocol already defines that there
 * is a header `Authorization` that should be used for passing authorization information. In most cases you will see that
 * tokens are sent as bearer tokens, i.e.: `Authorization: Bearer some+base64+string`.
 *
 * === Authenticating (AuthN)
 *
 * For this provider a user is authenticated if the token passes the signature checks and that the token is not expired.
 * For this reason it is imperative that private keys are kept private and not copy pasted across project since it would
 * be a security hole.
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthJWTExamples#example9}
 * ----
 *
 * In a nutshell the provider is checking for several things:
 *
 * * token signature is valid against internal private key
 * * fields: `exp`, `iat`, `nbf`, `audience`, `issuer` are valid according to the config
 *
 * If all these are valid then the token is considered good and a user object is returned.
 *
 * While the fields `exp`, `iat` and `nbf` are simple timestamp checks only `exp` can be configured to be ignored:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthJWTExamples#example10}
 * ----
 *
 * In order to verify the `aud` field one needs to pass the options like before:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthJWTExamples#example11}
 * ----
 *
 * And the same for the issuer:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthJWTExamples#example12}
 * ----
 *
 * === Authorizing (AuthZ)
 *
 * Once a token is parsed and is valid we can use it to perform authorization tasks. The most simple is to verify if a
 * user has a specific authority. In this case one needs to to:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthJWTExamples#example13}
 * ----
 *
 * By default the provider will lookup under the key `permissions` but like the other providers one can extend the
 * concept to authorities to roles by using the `:` as a splitter, so `role:authority` can be used to lookup the token.
 *
 * Since JWT are quite free form and there is no standard on where to lookup for the claims the location can be
 * configured to use something else than `permissions`, for example one can even lookup under a path like this:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthJWTExamples#example14}
 * ----
 *
 * So in this example we configure the JWT to work with Keycloak token format. In this case the claims will be checked
 * under the path `realm_access/roles` rather than `permissions`.
 *
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="http://tfox.org">Tim Fox</a>
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
@Document(fileName = "index.adoc")
@ModuleGen(name = "vertx-auth-jwt", groupPackage = "io.vertx")
package io.vertx.ext.auth.jwt;

import io.vertx.codegen.annotations.ModuleGen;
import io.vertx.docgen.Document;
