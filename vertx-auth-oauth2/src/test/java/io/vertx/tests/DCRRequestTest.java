package io.vertx.tests;

import org.junit.Before;
import org.junit.Test;
import io.vertx.core.json.JsonObject;

import io.vertx.ext.auth.oauth2.DCRRequest;

public class DCRRequestTest {

  private static final String DCR_REQUEST_STRING = "{\n" +
    "  \"clientId\": \"my-client-id\",\n" +
    "  \"registrationAccessToken\": \"my-registration-access-token\"\n" +
    "}";

  private DCRRequest dcrRequest;

  @Before
  public void setup() {
    this.dcrRequest = new DCRRequest(new JsonObject(DCR_REQUEST_STRING));
  }

  @Test
  public void testCreateFromJson() {
    assert "my-client-id".equals(dcrRequest.getClientId());
    assert "my-registration-access-token".equals(dcrRequest.getRegistrationAccessToken());
  }

  @Test
  public void testToJson() {
    io.vertx.core.json.JsonObject json = dcrRequest.toJson();
    assert "my-client-id".equals(json.getString("clientId"));
    assert "my-registration-access-token".equals(json.getString("registrationAccessToken"));
  }
}
