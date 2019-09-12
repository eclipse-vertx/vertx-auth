package io.vertx.ext.auth.oauth2;

import org.junit.Test;

import static org.junit.Assert.*;

public class OAuth2ClientOptionsTest {

  @Test
  public void testMSLikeConfig() {
    OAuth2ClientOptions config = new OAuth2ClientOptions();

    config
      .setClientID("6731de76-14a6-49ae-97bc-6eba6914391e")
      .setSite("https://login.microsoftonline.com/{tenant}");

    assertEquals("https://login.microsoftonline.com/6731de76-14a6-49ae-97bc-6eba6914391e", config.getSite());
  }
}
