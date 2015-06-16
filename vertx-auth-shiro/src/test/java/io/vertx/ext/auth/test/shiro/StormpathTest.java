package io.vertx.ext.auth.test.shiro;

import com.stormpath.sdk.api.ApiKey;
import com.stormpath.sdk.api.ApiKeys;
import com.stormpath.sdk.client.Client;
import com.stormpath.sdk.client.Clients;
import com.stormpath.shiro.realm.ApplicationRealm;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;

public class StormpathTest extends VertxTestBase {

  protected AuthProvider authProvider;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    // Setup our shiro+stormpath+vertx integration
    File file = ((VertxInternal) vertx).resolveFile("stormpath.properties");
    ApiKey apiKey = ApiKeys.builder().setFileLocation(file.getAbsolutePath()).build();
    Client client = Clients.builder().setApiKey(apiKey).build();
    ApplicationRealm stormpathAppRealm = new ApplicationRealm();
    stormpathAppRealm.setClient(client);
    stormpathAppRealm.setApplicationRestUrl("https://api.stormpath.com/v1/accounts/5W1RoooMzoo0XqKMx15IEi");
    authProvider = ShiroAuth.create(vertx, stormpathAppRealm);
  }

  @Test
  @Ignore
  public void testIntegration() {
    JsonObject credentials = new JsonObject()
        .put("username", "testname@test.com")
        .put("password", "890fup*()");

    authProvider.authenticate(credentials, auth -> {
      if (auth.failed()) {
        fail(auth.cause().getMessage());
      } else {
        assertTrue(auth.succeeded());
        testComplete();
      }
    });
    await();
  }
}
