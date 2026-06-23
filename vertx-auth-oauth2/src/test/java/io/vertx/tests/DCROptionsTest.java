package io.vertx.tests;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import io.vertx.core.json.JsonObject;

import io.vertx.ext.auth.oauth2.DCROptions;

public class DCROptionsTest {

  private static final String DCR_OPTION_JSO_STRING = "{\n" +
    "  \"site\": \"https://auth.example.com\",\n" +
    "  \"tenant\": \"master\",\n" +
    "  \"initialAccessToken\": \"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0\",\n" +
    "  \"httpClientOptions\": {\n" +
    "    \"defaultHost\": \"auth.example.com\"\n" +
    "  }\n" +
    "}\n" +
    "";

  private DCROptions dcrOptions;

  @Before
  public void setup() {
    dcrOptions = new DCROptions(new JsonObject(DCR_OPTION_JSO_STRING));
  }

  @Test
  public void testCreateFromJson() {
    assertEquals("https://auth.example.com", dcrOptions.getSite());
    assertEquals("master", dcrOptions.getTenant());
    assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0", dcrOptions.getInitialAccessToken());
    assertEquals("auth.example.com", dcrOptions.getHttpClientOptions().getDefaultHost());
  }

  @Test
  public void testSerializationToJson() {
    io.vertx.core.json.JsonObject json = dcrOptions.toJson();
    assertEquals("https://auth.example.com", json.getString("site"));
    assertEquals("master", json.getString("tenant"));
    assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0", json.getString("initialAccessToken"));
    assertEquals("auth.example.com",
      json.getJsonObject("httpClientOptions").getString("defaultHost"));
  }
}
