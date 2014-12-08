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

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthRealmType;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.LDAPAuthRealmConstants;
import io.vertx.test.core.VertxTestBase;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class LDAPAuthServiceTest extends VertxTestBase {

  @Rule
  public TemporaryFolder ldapWorkingDirectory = new TemporaryFolder();

  protected EmbeddedADS ldapServer;
  protected AuthService authService;

  protected JsonObject getConfig() {
    JsonObject config = new JsonObject();
    config.put(LDAPAuthRealmConstants.LDAP_URL, "ldap://localhost:10389");
    config.put(LDAPAuthRealmConstants.LDAP_USER_DN_TEMPLATE_FIELD, "uid={0},ou=users,dc=foo,dc=com");
    config.put(AuthService.AUTH_REALM_TYPE_FIELD, AuthRealmType.LDAP.toString());
    return config;
  }

  @Test
  public void testLDAP() {
    authService = AuthService.create(vertx, getConfig());
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testLDAPFailBadpassword() {
    authService = AuthService.create(vertx, getConfig());
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "wrongone");
    authService.login(credentials, onSuccess(res -> {
      assertFalse(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testLDAPFailUnknownUser() {
    authService = AuthService.create(vertx, getConfig());
    JsonObject credentials = new JsonObject().put("username", "bob").put("password", "blah");
    authService.login(credentials, onSuccess(res -> {
      assertFalse(res);
      testComplete();
    }));
    await();
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    ldapServer = new EmbeddedADS(ldapWorkingDirectory.newFolder());
    ldapServer.startServer();
    insertTestUsers();
  }

  /*
   * insert test users (only one currently), if we need more users, it would be
   * better to use a ldif file
   */
  private void insertTestUsers() throws LDAPException {
    LDAPConnection connection = null;
    try {
      connection = new LDAPConnection("localhost", 10389);

      // entry tim/sausages
      List<Attribute> addRequest = new ArrayList<Attribute>();
      addRequest.add(new Attribute("objectClass", "top"));
      addRequest.add(new Attribute("objectClass", "person"));
      addRequest.add(new Attribute("objectClass", "organizationalPerson"));
      addRequest.add(new Attribute("objectClass", "inetOrgPerson"));
      addRequest.add(new Attribute("cn", "Tim Fox"));
      addRequest.add(new Attribute("sn", "Fox"));
      addRequest.add(new Attribute("mail", "tim@example.com"));
      addRequest.add(new Attribute("uid", "tim"));
      addRequest.add(new Attribute("userPassword", "{ssha}d0M5Z2qjOOCSCQInvZHgVAleCqU5I+ag9ZHXMw=="));

      connection.add("uid=tim,ou=users,dc=foo,dc=com", addRequest);
    } finally {
      if (connection != null) {
        connection.close();
      }
    }
  }

  @Override
  protected void tearDown() throws Exception {
    ldapServer.stopServer();
    super.tearDown();
  }
}
