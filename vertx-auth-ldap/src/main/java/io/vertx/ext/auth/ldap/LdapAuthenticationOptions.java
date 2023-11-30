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
package io.vertx.ext.auth.ldap;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

/**
 * Ldap auth configuration options
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class LdapAuthenticationOptions {

  private String authenticationMechanism;
  private String referral;
  private String url;
  private String authenticationQuery;

  public LdapAuthenticationOptions() {
  }

  public LdapAuthenticationOptions(JsonObject json) {
    this();
    LdapAuthenticationOptionsConverter.fromJson(json, this);
  }

  public String getAuthenticationMechanism() {
    return authenticationMechanism;
  }

  public String getReferral() {
    return referral;
  }

  public String getUrl() {
    return url;
  }

  public String getAuthenticationQuery() {
    return authenticationQuery;
  }

  /**
   * sets the authentication mechanism. default to 'simple' if not set
   *
   * @param authenticationMechanism
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setAuthenticationMechanism(String authenticationMechanism) {
    this.authenticationMechanism = authenticationMechanism;
    return this;
  }

  /**
   * Set the referral property. Default to 'follow' if not set
   *
   * @param referral the referral
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setReferral(String referral) {
    this.referral = referral;
    return this;
  }

  /**
   * Set the url to the LDAP server. The url must start with `ldap://` and a port
   * must be specified.
   *
   * @param url the url to the server
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setUrl(String url) {
    this.url = url;
    return this;
  }

  /**
   * Set the query to use to authenticate a user. This is used to determine the
   * actual lookup to use when looking up a user with a particular id. An example
   * is `uid={0},ou=users,dc=foo,dc=com` - Note that the element `{0}` is
   * substituted with the user id to create the actual lookup.
   *
   * @param authenticationQuery
   * @return a reference to this, so the API can be used fluently
   */
  public LdapAuthenticationOptions setAuthenticationQuery(String authenticationQuery) {
    this.authenticationQuery = authenticationQuery;
    return this;
  }

}
