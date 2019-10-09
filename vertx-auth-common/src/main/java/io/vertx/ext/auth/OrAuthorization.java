package io.vertx.ext.auth;

import java.util.List;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.OrAuthorizationImpl;

/**
 * Allows to perform a logical 'or' between several authorizations
 * 
 * @author <a href="mailto:stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 * 
 */
@VertxGen
public interface OrAuthorization extends Authorization {

	static OrAuthorization create() {
		return new OrAuthorizationImpl();
	}
	
	List<Authorization> getAuthorizations();

	OrAuthorization addAuthorization(Authorization authorization);

}
