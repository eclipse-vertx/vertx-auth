package io.vertx.ext.auth.test.jwt;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.jwt.impl.JWTAuthProviderImpl;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.*;

public class RaceTest {

  private static final KeyStoreOptions AUTH_OPTIONS = new KeyStoreOptions()
    .setPath("keystore-race.jceks")
    .setType("jceks")
    .setPassword("secret");

  private static final Credentials CREDENTIALS = new TokenCredentials("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIiwiaWF0IjoxNjI5ODE3NDI5fQ.frtNqWYEeFsO4N_IT4WkjhDo0Tqx_gfaLrPYQwpfRf0");

  private static final JsonObject CLAIMS = new JsonObject().put("field", "value");

  private JWTAuth authProvider;
  private Vertx vertx;

  @Before
  public void initial() {
    vertx = Vertx.vertx();
    authProvider = new JWTAuthProviderImpl(vertx, new JWTAuthOptions().setKeyStore(AUTH_OPTIONS));
  }

  @After
  public void shutdown() throws ExecutionException, InterruptedException {
    vertx.close().toCompletionStage().toCompletableFuture().get();
  }

  @Test
  public void shouldNotThrowAnyErrors() throws InterruptedException, ExecutionException {
    final ExecutorService executor = Executors.newFixedThreadPool(5000);
    final Collection<Callable<Void>> jobs = new ArrayList<>();
    for (int i = 0; i < 2500; i++) {
      jobs.add(() -> {
        final CompletableFuture<Void> future = new CompletableFuture<>();
        authProvider.authenticate(CREDENTIALS, res -> {
          if (res.failed()) {
            res.cause().printStackTrace();
            future.completeExceptionally(res.cause());
          } else {
            future.complete(null);
          }
        });
        return future.get();
      });

      jobs.add(() -> {
        authProvider.generateToken(CLAIMS);
        return null;
      });
    }

    final List<Future<Void>> results = executor.invokeAll(jobs);
    for (final Future<Void> f : results) {
      f.get();
    }
    executor.shutdown();
    executor.awaitTermination(2000, TimeUnit.SECONDS);
  }
}
