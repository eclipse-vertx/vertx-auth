/*
 * Copyright 2015 Red Hat, Inc.
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
 * == The OAuth2 auth provider
 *
 * This component contains an out of the box OAuth2 implementation. To use this project, add the following
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
 * OAuth2 lets users grant the access to the desired resources to third party applications, giving them the possibility
 * to enable and disable those accesses whenever they want.
 *
 * Vert.x OAuth2 supports the following flows.
 *
 * * Authorization Code Flow (for apps with servers that can store persistent information).
 * * Password Credentials Flow (when previous flow can't be used or during development).
 * * Client Credentials Flow (the client can request an access token using only its client credentials)
 *
 * === Authorization Code Flow
 *
 * The authorization code grant type is used to obtain both access tokens and refresh tokens and is optimized for
 * confidential clients. As a redirection-based flow, the client must be capable of interacting with the resource
 * owner's user-agent (typically a web browser) and capable of receiving incoming requests (via redirection) from the
 * authorization server.
 *
 * For more details see http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1[Oauth2 specification, section 4.1].
 *
 * === Password Credentials Flow
 *
 * The resource owner password credentials grant type is suitable in cases where the resource owner has a trust
 * relationship with the client, such as the device operating system or a highly privileged application. The
 * authorization server should take special care when enabling this grant type, and only allow it when other flows are
 * not viable.
 *
 * The grant type is suitable for clients capable of obtaining the resource owner's credentials (username and password,
 * typically using an interactive form).  It is also used to migrate existing clients using direct authentication
 * schemes such as HTTP Basic or Digest authentication to OAuth by converting the stored credentials to an access token.
 *
 * For more details see http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.3[Oauth2 specification, section 4.3].
 *
 * === Client Credentials Flow
 *
 * The client can request an access token using only its client credentials (or other supported means of authentication)
 * when the client is requesting access to the protected resources under its control, or those of another resource owner
 * that have been previously arranged with the authorization server (the method of which is beyond the scope of this
 * specification).
 *
 * The client credentials grant type MUST only be used by confidential clients.
 *
 * For more details see http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.4[Oauth2 specification, section 4.4].
 *
 * === Getting Started
 *
 * An example on how to use this provider and authenticate with GitHub can be implemented as:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example1}
 * ----
 *
 * ==== Authorization Code flow
 *
 * The Authorization Code flow is made up from two parts. At first your application asks to the user the permission to
 * access their data. If the user approves the OAuth2 server sends to the client an authorization code. In the second
 * part, the client POST the authorization code along with its client secret to the authority server in order to get the
 * access token.
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example2}
 * ----
 *
 * ==== Password Credentials Flow
 *
 * This flow is suitable when the resource owner has a trust relationship with the client, such as its computer
 * operating system or a highly privileged application. Use this flow only when other flows are not viable or when you
 * need a fast way to test your application.
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example3}
 * ----
 *
 * ==== Client Credentials Flow
 *
 * This flow is suitable when client is requesting access to the protected resources under its control.
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example4}
 * ----
 *
 * === AccessToken object
 *
 * When a token expires we need to refresh it. OAuth2 offers the AccessToken class that add a couple of useful methods
 * to refresh the access token when it is expired.
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example5}
 * ----
 *
 * When you've done with the token or you want to log out, you can revoke the access token and refresh token.
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example6}
 * ----
 *
 * === Example configuration for common OAuth2 providers
 *
 * For convenience there are several helpers to assist your with your configuration. Currently we provide:
 *
 * * App.net {@link io.vertx.ext.auth.oauth2.providers.AppNetAuth}
 * * Azure Active Directory {@link io.vertx.ext.auth.oauth2.providers.AzureADAuth}
 * * Facebook {@link io.vertx.ext.auth.oauth2.providers.FacebookAuth}
 * * Github {@link io.vertx.ext.auth.oauth2.providers.GithubAuth}
 * * Google {@link io.vertx.ext.auth.oauth2.providers.GoogleAuth}
 * * Instagram {@link io.vertx.ext.auth.oauth2.providers.InstagramAuth}
 * * Keycloak {@link io.vertx.ext.auth.oauth2.providers.KeycloakAuth}
 * * LinkedIn {@link io.vertx.ext.auth.oauth2.providers.LinkedInAuth}
 * * Salesforce {@link io.vertx.ext.auth.oauth2.providers.SalesforceAuth}
 * * Shopify {@link io.vertx.ext.auth.oauth2.providers.ShopifyAuth}
 * * Twitter {@link io.vertx.ext.auth.oauth2.providers.TwitterAuth}
 *
 * ==== JBoss Keycloak
 *
 * When using this Keycloak the provider has knowledge on how to parse access tokens and extract grants from inside.
 * This information is quite valuable since it allows to do authorization at the API level, for example:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example13}
 * ----
 *
 * We also provide a helper class for Keycloak so that we can we can easily retrieve decoded token and some necessary
 * data (e.g. `preferred_username`) from the Keycloak principal. For example:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthOAuth2Examples#example14}
 * ----
 *
 */
@Document(fileName = "index.adoc")
@ModuleGen(name = "vertx-auth-oauth2", groupPackage = "io.vertx")
package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.ModuleGen;
import io.vertx.docgen.Document;
