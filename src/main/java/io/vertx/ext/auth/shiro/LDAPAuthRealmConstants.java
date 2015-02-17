/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl_v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.shiro;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public interface LDAPAuthRealmConstants {

  static final String LDAP_USER_DN_TEMPLATE_FIELD = "ldap_user_dn_template";
  static final String LDAP_URL = "ldap_url";
  static final String LDAP_AUTHENTICATION_MECHANISM = "ldap_authentication_mechanism";
  static final String LDAP_CONTEXT_FACTORY_CLASS_NAME = "ldap_context_factory_class_name";
  static final String LDAP_POOLING_ENABLED = "ldap_pooling_enabled";
  static final String LDAP_REFERRAL = "ldap_referral";
  static final String LDAP_SYSTEM_USERNAME = "ldap_system_username";
  static final String LDAP_SYSTEM_PASSWORD = "ldap_system_password";

}
