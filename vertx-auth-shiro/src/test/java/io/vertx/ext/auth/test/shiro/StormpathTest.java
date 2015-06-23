package io.vertx.ext.auth.test.shiro;

import com.stormpath.sdk.api.ApiKey;
import com.stormpath.sdk.api.ApiKeys;
import com.stormpath.sdk.client.Client;
import com.stormpath.sdk.client.Clients;
import com.stormpath.shiro.realm.ApplicationRealm;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.ext.auth.shiro.impl.ShiroUser;
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
    stormpathAppRealm.setApplicationRestUrl("https://api.stormpath.com/v1/applications/2oFtzixwgN0wYKt25euKpg");
    authProvider = ShiroAuth.create(vertx, stormpathAppRealm);
  }

  @Test
  @Ignore
  public void testIntegration() {
    JsonObject credentials = new JsonObject()
        .put("username", "dummy")
        .put("password", "Pwd12345678");

    authProvider.authenticate(credentials, auth -> {
      if (auth.failed()) {
        fail(auth.cause().getMessage());
      } else {
        assertTrue(auth.succeeded());
        auth.result().isAuthorised("role:https://api.stormpath.com/v1/groups/5z3pdGOZ2y3jb2ONjAQHiT", r-> {
          if (r.failed()) {
            fail(r.cause().getMessage());
          } else {
            assertTrue(r.result());
            testComplete();
          }
        });
      }
    });
    await();
  }

  @Test
  @Ignore
  public void testIntegrationWithSerialization() {
    ShiroUser user = new ShiroUser();

    String username = "https://api.stormpath.com/v1/accounts/5eNEPGUEwYNkC6EM5ODdJz";
    String prefix = "role:";

    Buffer b = Buffer.buffer()
        // no cached permissions
        .appendInt(0)
        // username
        .appendInt(username.length())
        .appendString(username)
        // prefix
        .appendInt(prefix.length())
        .appendString(prefix);

    user.readFromBuffer(0, b);
    user.setAuthProvider(authProvider);

    user.isAuthorised("role:https://api.stormpath.com/v1/groups/5z3pdGOZ2y3jb2ONjAQHiT", r -> {
      if (r.failed()) {
        fail(r.cause().getMessage());
      } else {
        assertTrue(r.result());
        testComplete();
      }
    });
    await();
  }
}
