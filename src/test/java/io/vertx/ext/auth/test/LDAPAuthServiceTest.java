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

package io.vertx.ext.auth.test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthRealmType;
import io.vertx.ext.auth.AuthService;
import io.vertx.test.core.VertxTestBase;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class LDAPAuthServiceTest extends VertxTestBase {

  @Rule
  public TemporaryFolder ldapWorkingDirectory = new TemporaryFolder();

  protected EmbeddedADSVer157 ldapServer;
  protected AuthService authService;

  protected JsonObject getConfig() {
    JsonObject config = new JsonObject();
    config.put("ldap_url", "ldap://localhost:10389");
    config.put("ldap_user_dn_template", "uid={0},ou=users,dc=foo,dc=com");
    return config;
  }

  // FIXME - currently commented out as can't figure out LDAP schema shit
  @Test
  @Ignore
  public void testLDAP() {
    authService = AuthService.create(vertx, AuthRealmType.LDAP, getConfig());
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    ldapServer = new EmbeddedADSVer157(ldapWorkingDirectory.newFolder());
    ldapServer.startServer();
  }

  @Override
  protected void tearDown() throws Exception {
    ldapServer.stopServer();
    super.tearDown();
  }
}
