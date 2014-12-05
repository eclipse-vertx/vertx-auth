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

package io.vertx.ext.auth.impl.realms;

import io.vertx.core.json.JsonObject;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.ldap.JndiLdapContextFactory;
import org.apache.shiro.realm.ldap.JndiLdapRealm;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class LDAPAuthRealm extends ShiroAuthRealm {

  public LDAPAuthRealm() {
  }

  @Override
  public void init(JsonObject config) {
    JndiLdapContextFactory fact;
    this.config = config;
    JndiLdapRealm ldapRealm = new JndiLdapRealm();
    JndiLdapContextFactory factory = new JndiLdapContextFactory();
    String userDNTemplate = config.getString("ldap_user_dn_template");
    if (userDNTemplate != null) {
      ldapRealm.setUserDnTemplate(userDNTemplate);
    }
    String url = config.getString("ldap_url");
    if (url != null) {
      factory.setUrl(url);
    }
    String authenticationMechanism = config.getString("ldap_authentication_mechanism");
    if (authenticationMechanism != null) {
      factory.setAuthenticationMechanism(authenticationMechanism);
    }
    String contextFactoryClassName = config.getString("ldap_context_factory_class_name");
    if (contextFactoryClassName != null) {
      factory.setContextFactoryClassName(contextFactoryClassName);
    }
    boolean poolingEnabled = config.getBoolean("ldap_pooling_enabled", false);
    factory.setPoolingEnabled(poolingEnabled);
    String referral = config.getString("ldap_referral");
    if (referral != null) {
      factory.setReferral(referral);
    }
    String systemUsername = config.getString("ldap_system_username");
    if (systemUsername != null) {
      factory.setSystemUsername(systemUsername);
    }
    String systemPassword = config.getString("ldap_system_password");
    if (systemPassword != null) {
      factory.setSystemPassword(systemPassword);
    }

    ldapRealm.setContextFactory(factory);
    ldapRealm.init();
    this.securityManager = new DefaultSecurityManager(ldapRealm);
    this.realm = ldapRealm;
  }


}
