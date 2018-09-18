package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2RBAC;
import io.vertx.ext.jwt.JWT;
import io.vertx.ext.jwt.JWTOptions;

import java.util.Base64;
import java.util.regex.Pattern;

public abstract class OAuth2UserImpl extends AbstractUser implements AccessToken {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2UserImpl.class);

  // state
  private JsonObject principal;
  // runtime
  private transient OAuth2AuthProviderImpl provider;
  private transient OAuth2RBAC rbac;
  // decoded state
  protected transient JsonObject accessToken;
  protected transient JsonObject refreshToken;
  protected transient JsonObject idToken;

  public OAuth2UserImpl() {
  }

  public OAuth2UserImpl(OAuth2Auth provider, JsonObject principal) {
    this.principal = principal;
    setAuthProvider(provider);
  }

  protected void init(JsonObject json) {
    // the permission cache needs to be clear
    clearCache();
    // update the principal
    principal = json;

    if (principal != null) {
      // if the expires at is already set, this principal is already setup
      if (!principal.containsKey("expires_at") && principal.containsKey("expires_in")) {
        Long expiresIn;
        try {
          expiresIn = principal.getLong("expires_in");
        } catch (ClassCastException e) {
          // for some reason someone decided to send a number as a String...
          expiresIn = Long.valueOf(principal.getString("expires_in"));
        }
        principal.put("expires_at", System.currentTimeMillis() + 1000 * expiresIn);
      }

      // attempt to decode tokens
      if (provider != null) {
        accessToken = decodeToken("access_token");
        // re-compute expires at if not present and access token has been successfully decoded from JWT
        if (!principal.containsKey("expires_at") && accessToken != null) {
          Long exp = accessToken.getLong("exp");
          if (exp != null) {
            principal.put("expires_at", exp * 1000);
          }
        }
        refreshToken = decodeToken("refresh_token");
        idToken = decodeToken("id_token");
        // rebuild cache
        String scope = principal.getString("scope");
        // avoid the case when scope is the literal "null" value.
        if (scope != null) {
          for (String authority : scope.split(Pattern.quote(provider.getConfig().getScopeSeparator()))) {
            cachePermission(authority);
          }
        }
      }
    }
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    provider = (OAuth2AuthProviderImpl) authProvider;
    rbac = provider.getRBACHandler();
    // re-attempt to decode tokens
    init(principal);
  }

  protected OAuth2AuthProviderImpl getProvider() {
    return provider;
  }

  @Override
  public JsonObject principal() {
    return principal;
  }

  @Override
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    if (expired()) {
      resultHandler.handle(Future.failedFuture("Expired Token"));
      return;
    }

    if (rbac == null) {
      resultHandler.handle(Future.failedFuture("No RBAC Handler available"));
    } else {
      rbac.isAuthorized(this, permission, resultHandler);
    }
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    if (principal != null) {
      Buffer buffer = principal.toBuffer();
      buff.appendInt(buffer.length());
      buff.appendBuffer(buff);
    } else {
      buff.appendInt(0);
    }
  }

  @Override
  public int readFromBuffer(int pos, Buffer buff) {
    pos = super.readFromBuffer(pos, buff);
    int len = buff.getInt(pos);
    pos += 4;
    if (len > 0) {
      Buffer buffer = buff.getBuffer(pos, pos + len);
      principal = new JsonObject(buffer);
      pos += len;
    } else {
      principal.clear();
    }
    // re-attempt to decode tokens
    init(principal);
    return pos;
  }

  protected JsonObject decodeToken(String tokenType) {
    return decodeToken(tokenType, false);
  }

  protected JsonObject decodeToken(String tokenType, boolean trust) {

    final Object opaque = principal.getValue(tokenType);

    if (opaque == null) {
      return null;
    }

    if (opaque instanceof JsonObject) {
      // already decoded
      return (JsonObject) opaque;
    }

    try {
      if (trust) {
        String[] segments = ((String) opaque).split("\\.");
        if (segments.length == 2 || segments.length == 3) {
          // All segment should be base64
          String payloadSeg = segments[1];
          // base64 decode and parse JSON
          return new JsonObject(Buffer.buffer(Base64.getUrlDecoder().decode(payloadSeg)));
        }
      } else {
        return provider.getJWT().decode(((String) opaque));
      }
    } catch (RuntimeException e) {
      // explicity catch and log as debug. exception here is a valid case
      // the reason is that it can be for several factors, such as bad token
      // or invalid JWT key setup, in that case we fall back to opaque token
      // which is the default operational mode for OAuth2.
      LOG.debug("Cannot decode token:", e);
    }
    return null;
  }

  @Override
  public String opaqueAccessToken() {
    return principal.getString("access_token");
  }

  @Override
  public String opaqueRefreshToken() {
    return principal.getString("refresh_token");
  }

  @Override
  public String opaqueIdToken() {
    return principal.getString("id_token");
  }

  @Override
  public JsonObject accessToken() {
    if (accessToken != null) {
      return accessToken.copy();
    }
    return null;
  }

  @Override
  public JsonObject refreshToken() {
    if (refreshToken != null) {
      return refreshToken.copy();
    }
    return null;
  }

  @Override
  public JsonObject idToken() {
    if (idToken != null) {
      return idToken.copy();
    }
    return null;
  }

  /**
   * Check if the access token is expired or not.
   */
  @Override
  public boolean expired() {
    if (principal == null) {
      return true;
    }

    if (accessToken != null) {
      // delegate to the JWT lib
      final JWT jwt = provider.getJWT();
      final JWTOptions options = provider.getConfig().getJWTOptions();
      try {
        jwt.isExpired(accessToken, options);
      } catch (RuntimeException e) {
        // explicit catch and log as debug.
        LOG.debug("Expired token:", e);
        return true;
      }
    }

    long now = System.currentTimeMillis();
    // expires_at is a computed field always in millis
    if (principal.containsKey("expires_at") && principal.getLong("expires_at", 0L) < now) {
      return true;
    }

    return false;
  }
}
