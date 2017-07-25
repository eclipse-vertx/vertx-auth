package io.vertx.ext.auth.htpasswd.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.htpasswd.HtpasswdAuth;
import io.vertx.ext.auth.htpasswd.HtpasswdAuthOptions;


import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.vertx.ext.auth.htpasswd.digest.Digest.*;

/**
 * An implementation of {@link HtpasswdAuth}
 *
 * @author Neven Radovanović
 */
public class HtpasswdAuthImpl implements HtpasswdAuth {

  private final Map<String, String> htUsers = new HashMap<>();
  private HtpasswdAuthOptions htpasswdAuthOptions;

  public HtpasswdAuthImpl(Vertx vertx, HtpasswdAuthOptions htpasswdAuthOptions) {
    this.htpasswdAuthOptions = htpasswdAuthOptions;

    for (String line : vertx.fileSystem().readFileBlocking(htpasswdAuthOptions.getHtpasswdFile()).toString().split("\\r?\\n")) {
      line = line.trim();

      if (line.isEmpty() || line.startsWith("#")) continue;

      Pattern entry = Pattern.compile("^([^:]+):(.+)");
      Matcher m = entry.matcher(line);
      if (m.matches()) {
        htUsers.put(m.group(1), m.group(2));
      }
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

    String storedPwd = htUsers.get(username);

    boolean authenticated = false;

    // BCrypt
    if (isBcryptHashed(storedPwd)) {
      if (bcryptCheck(password, storedPwd)) {
        authenticated = true;
      }
    }
    // test MD5 variant encrypted password
    else if (isMd5Hashed(storedPwd)) {
      if (md5Check(password, storedPwd)) {
        authenticated = true;
      }
    }
    // test unsalted SHA password
    else if (isShaHashed(storedPwd)) {
      if (shaCheck(password, storedPwd)) {
        authenticated = true;
      }
    }
    // test libc crypt() encoded password
    else if (htpasswdAuthOptions.isEnabledCryptPwd()) {
      if (cryptCheck(password, storedPwd)) {
        authenticated = true;
      }
    }
    // test clear text
    else if (htpasswdAuthOptions.isEnabledPlainTextPwd()) {
      if (storedPwd.equals(password)) {
        authenticated = true;
      }
    }

    if (authenticated) {
      resultHandler.handle(Future.succeededFuture(new HtpasswdUser(username, htpasswdAuthOptions.areUsersAuthorizedForEverything())));
    } else {
      resultHandler.handle(Future.failedFuture("Bad response"));
    }

  }


}
