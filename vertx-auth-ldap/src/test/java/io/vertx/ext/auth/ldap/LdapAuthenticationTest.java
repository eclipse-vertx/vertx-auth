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

import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.CreateLdapServerRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@CreateDS(name = "myDS", partitions = {@CreatePartition(name = "test", suffix = "dc=myorg,dc=com")})
@CreateLdapServer(transports = {@CreateTransport(protocol = "LDAP", address = "localhost")})
@ApplyLdifFiles({"ldap.ldif"})
@RunWith(VertxUnitRunner.class)
public class LdapAuthenticationTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @ClassRule
  public static final CreateLdapServerRule serverRule = new CreateLdapServerRule();
  private LdapAuthentication authProvider;

  @Test
  public void testSimpleAuthenticate(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    authProvider.authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testSimpleAuthenticateFailWrongPassword(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "wrongpassword");
    authProvider.authenticate(credentials)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Test
  public void testSimpleAuthenticateFailWrongUser(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("frank", "sausages");
    authProvider.authenticate(credentials)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Before
  public void setUp() throws Exception {
    LdapAuthenticationOptions ldapOptions = new LdapAuthenticationOptions().setUrl("ldap://localhost:" + serverRule.getLdapServer().getPort())
      .setAuthenticationQuery("uid={0},ou=Users,dc=myorg,dc=com");

    authProvider = LdapAuthentication.create(rule.vertx(), ldapOptions);
  }
}
