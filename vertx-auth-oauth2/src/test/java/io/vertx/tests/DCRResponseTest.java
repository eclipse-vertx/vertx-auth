package io.vertx.tests;

import org.junit.Before;
import org.junit.Test;

import io.vertx.core.json.JsonObject;

import io.vertx.ext.auth.oauth2.DCRResponse;

public class DCRResponseTest {

  private static final String DCR_RESPPONSE_STRING = "{\n" +
    "  \"id\": \"12345\",\n" +
    "  \"clientId\": \"my-client-id\",\n" +
    "  \"enabled\": true,\n" +
    "  \"clientAuthenticatorType\": \"client-secret\",\n" +
    "  \"secret\": \"my-secret\",\n" +
    "  \"registrationAccessToken\": \"my-registration-access-token\"\n" +
    "}";
  private DCRResponse dcrResponse;

  @Before
  public void setup() {
    this.dcrResponse = new DCRResponse(new JsonObject(DCR_RESPPONSE_STRING));
  }

  @Test
  public void testCreateFromJson() {
    assert "12345".equals(dcrResponse.getId());
    assert "my-client-id".equals(dcrResponse.getClientId());
    assert dcrResponse.isEnabled();
    assert "client-secret".equals(dcrResponse.getClientAuthenticatorType());
    assert "my-secret".equals(dcrResponse.getSecret());
    assert "my-registration-access-token".equals(dcrResponse.getRegistrationAccessToken());
  }

  @Test
  public void testSerializationToJson() {
    JsonObject json = dcrResponse.toJson();
    assert "12345".equals(json.getString("id"));
    assert "my-client-id".equals(json.getString("clientId"));
    assert json.getBoolean("enabled");
    assert "client-secret".equals(json.getString("clientAuthenticatorType"));
    assert "my-secret".equals(json.getString("secret"));
    assert "my-registration-access-token".equals(json.getString("registrationAccessToken"));
  }
}
