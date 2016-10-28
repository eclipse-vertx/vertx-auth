package io.vertx.groovy.ext.auth.oauth2;
public class GroovyStaticExtension {
  public static java.lang.String rawIdToken(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.rawIdToken(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.util.Map<String, Object> idToken(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.lang.groovy.RetroCompatExtension.fromJsonObject(io.vertx.ext.auth.oauth2.KeycloakHelper.idToken(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null));
  }
  public static java.lang.String rawAccessToken(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.rawAccessToken(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.util.Map<String, Object> accessToken(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.lang.groovy.RetroCompatExtension.fromJsonObject(io.vertx.ext.auth.oauth2.KeycloakHelper.accessToken(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null));
  }
  public static int authTime(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.authTime(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.lang.String sessionState(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.sessionState(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.lang.String acr(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.acr(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.lang.String name(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.name(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.lang.String email(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.email(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.lang.String preferredUsername(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.preferredUsername(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.lang.String nickName(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.ext.auth.oauth2.KeycloakHelper.nickName(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null);
  }
  public static java.util.Set<java.lang.String> allowedOrigins(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.util.Map<String, Object> principal) {
    return io.vertx.lang.groovy.RetroCompatExtension.applyIfNotNull(io.vertx.ext.auth.oauth2.KeycloakHelper.allowedOrigins(principal != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(principal) : null), list -> list.stream().map(elt -> elt).collect(java.util.stream.Collectors.toSet()));
  }
  public static java.util.Map<String, Object> parseToken(io.vertx.ext.auth.oauth2.KeycloakHelper j_receiver, java.lang.String token) {
    return io.vertx.lang.groovy.RetroCompatExtension.fromJsonObject(io.vertx.ext.auth.oauth2.KeycloakHelper.parseToken(token));
  }
  public static io.vertx.ext.auth.oauth2.OAuth2Auth createKeycloak(io.vertx.ext.auth.oauth2.OAuth2Auth j_receiver, io.vertx.core.Vertx vertx, io.vertx.ext.auth.oauth2.OAuth2FlowType flow, java.util.Map<String, Object> config) {
    return io.vertx.lang.groovy.RetroCompatExtension.wrap(io.vertx.ext.auth.oauth2.OAuth2Auth.createKeycloak(vertx,
      flow,
      config != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(config) : null));
  }
  public static io.vertx.ext.auth.oauth2.OAuth2Auth create(io.vertx.ext.auth.oauth2.OAuth2Auth j_receiver, io.vertx.core.Vertx vertx, io.vertx.ext.auth.oauth2.OAuth2FlowType flow, java.util.Map<String, Object> config) {
    return io.vertx.lang.groovy.RetroCompatExtension.wrap(io.vertx.ext.auth.oauth2.OAuth2Auth.create(vertx,
      flow,
      config != null ? new io.vertx.ext.auth.oauth2.OAuth2ClientOptions(io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(config)) : null));
  }
}
