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
import io.vertx.core.json.JsonObject;

/**
 * Ldap auth configuration options
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@DataObject(generateConverter = true)
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
   * sets the authentication mecanism 
   * 
   * @param authenticationMechanism
   * @return
   */
  public LdapAuthenticationOptions setAuthenticationMechanism(String authenticationMechanism) {
    this.authenticationMechanism = authenticationMechanism;
    return this;
  }

  public LdapAuthenticationOptions setReferral(String referral) {
    this.referral = referral;
    return this;
  }

  public LdapAuthenticationOptions setUrl(String url) {
    this.url = url;
    return this;
  }

  public LdapAuthenticationOptions setAuthenticationQuery(String userDnTemplate) {
    this.authenticationQuery = userDnTemplate;
    return this;
  }

}
