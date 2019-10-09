package io.vertx.ext.auth;

import java.util.List;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.AndAuthorizationImpl;

/**
 * Allows to perform a logical 'and' between several authorizations
 * 
 * @author <a href="mailto:stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 * 
 */
@VertxGen
public interface AndAuthorization extends Authorization {

	static AndAuthorization create() {
		return new AndAuthorizationImpl();
	}
	
	List<Authorization> getAuthorizations();

	AndAuthorization addAuthorization(Authorization authorization);

}
