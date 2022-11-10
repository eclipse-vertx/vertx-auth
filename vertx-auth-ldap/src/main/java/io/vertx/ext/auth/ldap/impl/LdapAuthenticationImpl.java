/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.ldap.impl;

import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Objects;

import javax.naming.Context;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import io.vertx.core.*;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.ldap.LdapAuthentication;
import io.vertx.ext.auth.ldap.LdapAuthenticationOptions;

/**
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
public class LdapAuthenticationImpl implements LdapAuthentication {
  private static final String SIMPLE_AUTHENTICATION_MECHANISM = "simple";
  private static final String FOLLOW_REFERRAL = "follow";

  private final Vertx vertx;
  private final LdapAuthenticationOptions authenticationOptions;

  public LdapAuthenticationImpl(Vertx vertx, LdapAuthenticationOptions authenticationOptions) {
    this.vertx = Objects.requireNonNull(vertx);
    this.authenticationOptions = Objects.requireNonNull(authenticationOptions);
  }

  @Override
  public Future<io.vertx.ext.auth.User> authenticate(JsonObject credentials) {
    return authenticate(new UsernamePasswordCredentials(credentials));
  }

  @Override
  public Future<io.vertx.ext.auth.User> authenticate(Credentials credentials) {
    final UsernamePasswordCredentials authInfo;
    try {
      authInfo = (UsernamePasswordCredentials) credentials;
      authInfo.checkValid(null);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    String ldapPrincipal = getLdapPrincipal(authInfo.getUsername());
    return createLdapContext(ldapPrincipal, authInfo.getPassword())
      .compose(ldapContext -> {
        User user = User.fromName(authInfo.getUsername());
        // metadata "amr"
        user.principal().put("amr", Collections.singletonList("pwd"));
        return Future.succeededFuture(user);
      });
  }

  private Future<LdapContext> createLdapContext(String principal, String credential) {
    Hashtable<String, Object> environment = new Hashtable<>();
    // set the initial cntext factory
    environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    // set the url
    environment.put(Context.PROVIDER_URL, authenticationOptions.getUrl());

    if (principal != null) {
      environment.put(Context.SECURITY_PRINCIPAL, principal);
    }
    if (credential != null) {
      environment.put(Context.SECURITY_CREDENTIALS, credential);
    }
    if (authenticationOptions.getAuthenticationMechanism() == null && (principal != null || credential != null)) {
      environment.put(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION_MECHANISM);
    }
    // referral
    environment.put(Context.REFERRAL,
      authenticationOptions.getReferral() == null ? FOLLOW_REFERRAL : authenticationOptions.getReferral());

    Promise<LdapContext> promise = ((VertxInternal) vertx).promise();

    vertx.executeBlocking(blockingResult -> {
      try {
        LdapContext context = new InitialLdapContext(environment, null);
        blockingResult.complete(context);
      } catch (Throwable t) {
        blockingResult.fail(t);
      }
    }, promise);

    return promise.future();
  }

  private String getLdapPrincipal(String principal) {
    return authenticationOptions.getAuthenticationQuery().replace("{0}", principal);
  }

}
