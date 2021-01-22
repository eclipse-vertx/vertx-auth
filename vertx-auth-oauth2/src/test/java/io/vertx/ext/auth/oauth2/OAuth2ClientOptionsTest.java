package io.vertx.ext.auth.oauth2;

import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.AzureADAuth;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(VertxUnitRunner.class)
public class OAuth2ClientOptionsTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test(expected = IllegalStateException.class)
  public void testMSLikeConfig() {
    OAuth2Options config = new OAuth2Options();

    config
      .setSite("https://login.microsoftonline.com/{tenant}")
      .replaceVariables(false);
  }

  @Test
  public void testMSLikeConfigCorrect() {
    OAuth2Options config = new OAuth2Options();

    config
      .setTenant("6731de76-14a6-49ae-97bc-6eba6914391e")
      .setSite("https://login.microsoftonline.com/{tenant}")
      .replaceVariables(false);

    assertEquals("https://login.microsoftonline.com/6731de76-14a6-49ae-97bc-6eba6914391e", config.getSite());
  }

  @Test
  public void testVariableReplacement() {
    OAuth2AuthProviderImpl auth = (OAuth2AuthProviderImpl) AzureADAuth.create(rule.vertx(), "clientId", "clientSecret", "guid");

    OAuth2Options config = auth.getConfig();

    assertEquals("https://login.microsoftonline.com/guid", config.getSite());
    assertEquals("guid", config.getExtraParameters().getString("resource"));
  }

  @Test
  public void TestTraillingSlash() {
    OAuth2Options config = new OAuth2Options();

    config
      .setSite("https://login.microsoftonline.com/")
      .replaceVariables(false);

    assertEquals("https://login.microsoftonline.com", config.getSite());
  }
}
