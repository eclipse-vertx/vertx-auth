package io.vertx.ext.auth.shiro;

import io.vertx.core.VertxException;
import io.vertx.ext.auth.AbstractAuthServiceVerticle;
import io.vertx.ext.auth.AuthService;

/**
 *
 * A verticle which starts an Auth service instance
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroAuthServiceVerticle extends AbstractAuthServiceVerticle {

  /**
   * The name of the field in the config which holds the name of the auth realm type to use,
   * e.g. PROPERTIES or LDAP
   */
  public static final String SHIRO_AUTH_REALM_TYPE = "auth_realm_type";

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

    // Create the service object
    return ShiroAuthService.create(vertx, type, config());
  }
}
