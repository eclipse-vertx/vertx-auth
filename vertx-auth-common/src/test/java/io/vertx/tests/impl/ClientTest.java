package io.vertx.tests.impl;

import io.vertx.ext.auth.Client;
import io.vertx.ext.auth.impl.ClientImpl.AuthMethod;
import io.vertx.ext.auth.impl.ClientImpl.GrantType;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ClientTest {

  @Test
  public void shouldCreateClient() {
    final Client client = Client.create("vert.x_is_the_best", GrantType.client_credentials,
      AuthMethod.client_secret_basic);
    assertEquals("vert.x_is_the_best", client.name());
    assertEquals(GrantType.client_credentials, client.grantTypes().get(0));
    assertEquals(AuthMethod.client_secret_basic, client.authMethod());
  }
}
