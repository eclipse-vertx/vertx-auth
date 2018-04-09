package io.vertx.ext.auth.htpasswd.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.htpasswd.HtpasswdAuth;
import io.vertx.ext.auth.htpasswd.HtpasswdAuthOptions;
import io.vertx.ext.auth.htpasswd.impl.hash.Plaintext;


import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An implementation of {@link HtpasswdAuth}
 *
 * @author Neven Radovanović
 */
public class HtpasswdAuthImpl implements HtpasswdAuth {

  private final HashingStrategy strategy = HashingStrategy.load();

  private final Map<String, String> htUsers = new HashMap<>();
  private HtpasswdAuthOptions options;

  public HtpasswdAuthImpl(Vertx vertx, HtpasswdAuthOptions options) {
    this.options = options;

    for (String line : vertx.fileSystem().readFileBlocking(options.getHtpasswdFile()).toString().split("\\r?\\n")) {
      line = line.trim();

      if (line.isEmpty() || line.startsWith("#")) continue;

      Pattern entry = Pattern.compile("^([^:]+):(.+)");
      Matcher m = entry.matcher(line);
      if (m.matches()) {
        htUsers.put(m.group(1), m.group(2));
      }
    }

    // handle the plain text vs crypt
    if (options.isEnablePlainText()) {
      // this will show a warning in the log
      strategy.put("", new Plaintext());
    }
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    String username = authInfo.getString("username");
    String password = authInfo.getString("password");

    // Null or empty username is invalid
    if (username == null || username.length() == 0) {
      resultHandler.handle((Future.failedFuture("Username must be set for authentication.")));
      return;
    }

    if (!htUsers.containsKey(username)) {
      resultHandler.handle((Future.failedFuture("Unknown username.")));
      return;
    }

    if (strategy.verify(htUsers.get(username), password)) {
      resultHandler.handle(Future.succeededFuture(new HtpasswdUser(username)));
    } else {
      resultHandler.handle(Future.failedFuture("Bad response"));
    }
  }
}
