package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.impl.OAuth2TokenImpl;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class Oauth2TokenTest extends VertxTestBase {

  final static JsonObject keycloakConfig = new JsonObject(
    "{\n" +
      "  \"realm\": \"master\",\n" +
      "  \"auth-server-url\": \"http://localhost:9000/auth\",\n" +
      "  \"ssl-required\": \"external\",\n" +
      "  \"resource\": \"frontend\",\n" +
      "  \"credentials\": {\n" +
      "    \"secret\": \"2fbf5e18-b923-4a83-9657-b4ebd5317f60\"\n" +
      "  }\n" +
      "}"
  );

  final static JsonObject keycloakToken = new JsonObject(
    "{\n" +
      "    \"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJZTnJLdkhxdkxWSW5BSUI5RDk4bGJlT1hMam9uVlh4T0hnTW5JMUU4dEo4In0.eyJqdGkiOiIwYTA4ZTA1NS1lNDEzLTQ5NzMtOWNmNS03MzQwN2E3NGZlMDYiLCJleHAiOjE1MDk1MzIwODMsIm5iZiI6MCwiaWF0IjoxNTA5NTMyMDIzLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdCIsInN1YiI6IjQ4MDgzMjhjLWIxZWEtNDVmNi05NWMyLTMwNGRmZTBiMTZiZiIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiI2NzlhYTM5NS00OWVlLTRmMTktODRiMi1lY2I2ZjYzMjdjZTIiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIn0.TQ_qC7Zq3Ga3Zbf_eSnaLe0f2bwTyKMwuNJ8CdGRoD4vGaAc3_hIweOFfnCMwQd1kYkn3TbK-tu3z7uLkrpN3snnBl8zCZcH2hueKP9c3x0HdzBXgPmHWraPZdmh6Oe9_PisfjOhlLUW02o2Us_WEAPerFGHHi2uCLQh8em3UiGTNA-p0VhvNTOkkuyQO6ZM0TAGZx5CUqXmBJO6O_rgcSVnRbXmyzpnbWHQNOfnb1SCcYEEOiVRFjBHpT1CVH12Fc475hDTmxUzK7F6CbMOh2lemhRQ-g8qSNuebYeQaqWz9EPOG1M6OV58krMWROxB_zagyo_ZabmvcuyNc4MDsA\",\n" +
      "    \"expires_in\":60,\n" +
      "    \"refresh_expires_in\":1800,\n" +
      "    \"refresh_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJZTnJLdkhxdkxWSW5BSUI5RDk4bGJlT1hMam9uVlh4T0hnTW5JMUU4dEo4In0.eyJqdGkiOiI0YWRkMWRmOC1mZDg0LTQ1NGYtYWIwZS1mMzUxYTM3ZTAzM2MiLCJleHAiOjE1MDk1MzM4MjMsIm5iZiI6MCwiaWF0IjoxNTA5NTMyMDIzLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdCIsInN1YiI6IjQ4MDgzMjhjLWIxZWEtNDVmNi05NWMyLTMwNGRmZTBiMTZiZiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ0ZXN0IiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiNjc5YWEzOTUtNDllZS00ZjE5LTg0YjItZWNiNmY2MzI3Y2UyIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsidmlldy1yZWFsbSIsInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX19.Fe2Q2dOpMm0YC31rqBduqJx8GZIGkG2h9xztR2aEWseq_ZwNVwFqX6T15HfGEESUmYzx-sZqAKWizHH93lKmcszkbvttD72gpxflAv3qFZgSW92wMfBH_vC3Mf1W4qFJk8GXYJ6qCyZJ49gtXG5IkzGHFtB0PJsvIQHovBrMZuGM6mgs1EP2MkMbLAOPuv4LDo004ZIMZMe7KJ40QIf34hIMnb-4-At-6tszZZ2UEcED_u2vxx4Jg9YAT3A3JAcwJlHoEkrq-5rSGfULPO4esWINGBeeGnTlTJUOZordaP4vbRLeHL2RQCDTSVkQVN4FBMtuezxibF95JNDStqRcfw\",\n" +
      "    \"token_type\":\"bearer\",\n" +
      "    \"not-before-policy\":0,\n" +
      "    \"session_state\":\"679aa395-49ee-4f19-84b2-ecb6f6327ce2\"\n" +
      "}"
  );

  private OAuth2Auth oauth2;

  @Test
  public void keycloakTest() throws Exception {
    super.setUp();
    oauth2 = KeycloakAuth.create(vertx, OAuth2FlowType.AUTH_CODE, keycloakConfig);

    OAuth2TokenImpl token = new OAuth2TokenImpl((OAuth2AuthProviderImpl) oauth2, keycloakToken);

    assertNotNull(token.opaqueAccessToken());
    assertNotNull(token.opaqueRefreshToken());
    assertNull(token.accessToken());
    // trust it
    token.setTrustJWT(true);
    assertNotNull(token.accessToken());
  }

  @Test
  public void testNullScope() throws Exception {
    super.setUp();
    oauth2 = KeycloakAuth.create(vertx, OAuth2FlowType.AUTH_CODE, keycloakConfig);

    JsonObject json = new JsonObject(
      "{\n" +
        "    \"access_token\":\"xyz\",\n" +
        "    \"expires_in\":60,\n" +
        "    \"token_type\":\"bearer\",\n" +
        "    \"not-before-policy\":0,\n" +
        "    \"scope\":null\n" +
        "}"
    );

    try {
      OAuth2TokenImpl token = new OAuth2TokenImpl((OAuth2AuthProviderImpl) oauth2, json);
    } catch (RuntimeException e) {
      fail();
    }
  }
}
