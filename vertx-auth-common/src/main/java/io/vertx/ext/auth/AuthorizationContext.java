package io.vertx.ext.auth;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.http.HttpServerRequest;

/**
 * The AuthorizationContext contains properties that can be used to match an Authorization
 * 
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@VertxGen
public interface AuthorizationContext {

    /**
    * Get the authenticated user
    * @return  the user
    */
	User user();

    /**
     * @return the HTTP request object
     */
	HttpServerRequest request();
	
}
