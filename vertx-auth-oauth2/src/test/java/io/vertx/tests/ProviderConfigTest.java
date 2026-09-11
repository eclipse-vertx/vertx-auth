package io.vertx.tests;

import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.DiscordAuth;
import io.vertx.ext.auth.oauth2.providers.OktaAuth;
import io.vertx.ext.auth.oauth2.providers.OryAuth;
import io.vertx.ext.auth.oauth2.providers.SpotifyAuth;
import io.vertx.ext.auth.oauth2.providers.TwitchAuth;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Verifies that the provider shortcuts configure the endpoints documented by each provider.
 * No network access is required: only the resulting {@link OAuth2Options} are inspected.
 */
@RunWith(VertxUnitRunner.class)
public class ProviderConfigTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static OAuth2Options configOf(OAuth2Auth auth) {
    return ((OAuth2AuthProviderImpl) auth).getConfig();
  }

  @Test
  public void testOryNetwork() {
    OAuth2Options cfg = configOf(OryAuth.create(rule.vertx(), "https://my-slug.projects.oryapis.com", "id", "secret"));
    assertEquals("id", cfg.getClientId());
    assertEquals("secret", cfg.getClientSecret());
    assertEquals("https://my-slug.projects.oryapis.com", cfg.getSite());
    assertEquals("/oauth2/auth", cfg.getAuthorizationPath());
    assertEquals("/oauth2/token", cfg.getTokenPath());
    assertEquals("/userinfo", cfg.getUserInfoPath());
    assertEquals("/oauth2/revoke", cfg.getRevocationPath());
    assertEquals("/oauth2/sessions/logout", cfg.getLogoutPath());
    assertEquals("/.well-known/jwks.json", cfg.getJwkPath());
    assertEquals(" ", cfg.getScopeSeparator());
  }

  @Test
  public void testOrySelfHostedTrailingSlash() {
    // self hosted hydra public API, trailing slash must be tolerated
    OAuth2Options cfg = configOf(OryAuth.create(rule.vertx(), "http://localhost:4444/", "id", "secret"));
    assertEquals("http://localhost:4444", cfg.getSite());
    assertEquals("/oauth2/token", cfg.getTokenPath());
  }

  @Test
  public void testOktaOrgAuthorizationServer() {
    OAuth2Options cfg = configOf(OktaAuth.create(rule.vertx(), "id", "secret", "dev-123456.okta.com"));
    assertEquals("id", cfg.getClientId());
    assertEquals("secret", cfg.getClientSecret());
    assertEquals("https://dev-123456.okta.com", cfg.getSite());
    assertEquals("/oauth2/v1/authorize", cfg.getAuthorizationPath());
    assertEquals("/oauth2/v1/token", cfg.getTokenPath());
    assertEquals("/oauth2/v1/userinfo", cfg.getUserInfoPath());
    assertEquals("/oauth2/v1/revoke", cfg.getRevocationPath());
    assertEquals("/oauth2/v1/introspect", cfg.getIntrospectionPath());
    assertEquals("/oauth2/v1/keys", cfg.getJwkPath());
    assertEquals("/oauth2/v1/logout", cfg.getLogoutPath());
    assertEquals(" ", cfg.getScopeSeparator());
  }

  @Test
  public void testOktaCustomAuthorizationServer() {
    OAuth2Options cfg = configOf(OktaAuth.create(rule.vertx(), "id", "secret", "dev-123456.okta.com", "default"));
    assertEquals("https://dev-123456.okta.com/oauth2/default", cfg.getSite());
    assertEquals("/v1/authorize", cfg.getAuthorizationPath());
    assertEquals("/v1/token", cfg.getTokenPath());
    assertEquals("/v1/userinfo", cfg.getUserInfoPath());
    assertEquals("/v1/revoke", cfg.getRevocationPath());
    assertEquals("/v1/introspect", cfg.getIntrospectionPath());
    assertEquals("/v1/keys", cfg.getJwkPath());
    assertEquals("/v1/logout", cfg.getLogoutPath());
  }

  @Test
  public void testDiscord() {
    OAuth2Options cfg = configOf(DiscordAuth.create(rule.vertx(), "id", "secret"));
    assertEquals("id", cfg.getClientId());
    assertEquals("secret", cfg.getClientSecret());
    assertEquals("https://discord.com/api", cfg.getSite());
    assertEquals("https://discord.com/oauth2/authorize", cfg.getAuthorizationPath());
    assertEquals("/oauth2/token", cfg.getTokenPath());
    assertEquals("/oauth2/token/revoke", cfg.getRevocationPath());
    assertEquals("/users/@me", cfg.getUserInfoPath());
    assertEquals(" ", cfg.getScopeSeparator());
  }

  @Test
  public void testTwitch() {
    OAuth2Options cfg = configOf(TwitchAuth.create(rule.vertx(), "id", "secret"));
    assertEquals("id", cfg.getClientId());
    assertEquals("secret", cfg.getClientSecret());
    assertEquals("https://id.twitch.tv/oauth2", cfg.getSite());
    assertEquals("/authorize", cfg.getAuthorizationPath());
    assertEquals("/token", cfg.getTokenPath());
    assertEquals("/userinfo", cfg.getUserInfoPath());
    assertEquals("/revoke", cfg.getRevocationPath());
    assertEquals("/keys", cfg.getJwkPath());
    assertEquals(" ", cfg.getScopeSeparator());
    // twitch only accepts client credentials in the request body
    assertFalse(cfg.isUseBasicAuthorization());
  }

  @Test
  public void testSpotify() {
    OAuth2Options cfg = configOf(SpotifyAuth.create(rule.vertx(), "id", "secret"));
    assertEquals("id", cfg.getClientId());
    assertEquals("secret", cfg.getClientSecret());
    assertEquals("https://accounts.spotify.com", cfg.getSite());
    assertEquals("/authorize", cfg.getAuthorizationPath());
    assertEquals("/api/token", cfg.getTokenPath());
    assertEquals("https://api.spotify.com/v1/me", cfg.getUserInfoPath());
    assertEquals(" ", cfg.getScopeSeparator());
    // spotify requires HTTP basic client authentication on the token endpoint
    assertTrue(cfg.isUseBasicAuthorization());
  }
}
