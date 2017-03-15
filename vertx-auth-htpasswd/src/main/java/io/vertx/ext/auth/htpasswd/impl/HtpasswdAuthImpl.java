package io.vertx.ext.auth.htpasswd.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.htpasswd.digest.BCrypt;
import io.vertx.ext.auth.htpasswd.HtpasswdAuth;
import io.vertx.ext.auth.htpasswd.HtpasswdAuthOptions;
import io.vertx.ext.auth.htpasswd.digest.Crypt;
import io.vertx.ext.auth.htpasswd.digest.DigestUtils;
import io.vertx.ext.auth.htpasswd.digest.Md5Crypt;


import java.util.Base64;
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

  private Logger logger = LoggerFactory.getLogger(HtpasswdAuthImpl.class);

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

//    Null or empty username is invalid
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
    if (storedPwd.startsWith("$2y$") || storedPwd.startsWith("$2a$")) {
      logger.warn("Currently bcrypt hashing algorithm is not supported. Can't authenticate user " + username);
      if (BCrypt.checkpw(password, storedPwd)) {
        authenticated = true;
      }
    }
// test MD5 variant encrypted password
    else if (storedPwd.startsWith("$apr1$")) {
      if (storedPwd.equals(Md5Crypt.apr1Crypt(password, storedPwd))) {
        authenticated = true;
      }
    }
// test unsalted SHA password
    else if (storedPwd.startsWith("{SHA}")) {
      String passwd64 = Base64.getEncoder().encodeToString(DigestUtils.sha1(password));
      if (storedPwd.substring("{SHA}".length()).equals(passwd64)) {
        authenticated = true;
      }
    }
// test libc crypt() encoded password
    else if (htpasswdAuthOptions.isEnabledCryptPwd() && storedPwd.equals(Crypt.crypt(password, storedPwd))) {
      authenticated = true;
    }
// test clear text
    else if (htpasswdAuthOptions.isEnabledPlainTextPwd() && storedPwd.equals(password)) {
      authenticated = true;
    }

    if (authenticated) {
      resultHandler.handle(Future.succeededFuture(new HtpasswdUser(username, htpasswdAuthOptions.areUsersAuthorizedForEverything())));
    } else {
      resultHandler.handle(Future.failedFuture("Bad response"));
    }

  }

}
