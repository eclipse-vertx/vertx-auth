package io.vertx.ext.auth.shiro;

import io.vertx.core.VertxException;
import io.vertx.ext.auth.AbstractAuthServiceVerticle;
import io.vertx.ext.auth.AuthService;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroAuthServiceVerticle extends AbstractAuthServiceVerticle {

  public static final String SHIRO_AUTH_REALM_TYPE = "auth_realm_type";
  public static final String REAPER_PERIOD = "reaper_period";

  @Override
  protected AuthService createService() {
    String realmType = config().getString(SHIRO_AUTH_REALM_TYPE);
    ShiroAuthRealmType type;
    if (realmType == null) {
      type = ShiroAuthRealmType.PROPERTIES;
    } else {
      try {
        type = ShiroAuthRealmType.valueOf(realmType);
      } catch (IllegalArgumentException e) {
        throw new VertxException("Invalid auth realm type: " + realmType);
      }
    }

    long reaperPeriod = config().getLong(REAPER_PERIOD, AuthService.DEFAULT_REAPER_PERIOD);

    // Create the service object
    return ShiroAuthService.create(vertx, type, config(), reaperPeriod);
  }
}
