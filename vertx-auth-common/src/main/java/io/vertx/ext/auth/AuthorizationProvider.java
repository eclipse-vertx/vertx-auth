package io.vertx.ext.auth;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;

/**
 * The role of an AuthorizationProvider is to return a set of Authorization.
 * Note that each AuthorizationProvider must provide its own unique Id
 * 
 * @author stephane bastian
 *
 */
@VertxGen
public interface AuthorizationProvider {

  /**
   * create an authorization provider with the specified id and authorizations
   * 
   * @param id
   * @param authorizations
   * @return
   */
  static AuthorizationProvider create(String id, Set<Authorization> authorizations) {
    Set<Authorization> _authorizations = new HashSet<>(Objects.requireNonNull(authorizations));
    return new AuthorizationProvider() {

      @Override
      public String getId() {
        return id;
      }

      @Override
      public void getAuthorizations(User user, Handler<AsyncResult<Set<Authorization>>> handler) {
        handler.handle(Future.succeededFuture(new HashSet<>(_authorizations)));
      }
    };
  }

  /**
   * returns the id of the authorization provider
   * 
   * @return
   */
  public String getId();

  /**
   * Returns the set of authorizations of the specified user
   * 
   * @param user
   * @param handler
   */
  public void getAuthorizations(User user, Handler<AsyncResult<Set<Authorization>>> handler);

}