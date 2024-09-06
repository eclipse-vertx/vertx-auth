package io.vertx.ext.auth.webauthn4j;

import java.util.List;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;

/**
 * Used to represent persistent storage of credentials, this gives you a way to abstract
 * how you want to store them (in memory, database, other). 
 */
@VertxGen
public interface CredentialStorage {

	/**
	 * Finds an existing list of credentials for a given user name and credential ID. 
	 * 
	 * Both the <code>userName</code> and <code>credentialId</code> parameters are optional
	 * but at least one of them must be specified. If only one is specified, it must match
	 * the results. If both are specified, then both must match the result at the same time.
	 * 
	 * This may return more than one element if one of the parameters is not set. If both are 
	 * set, then the returned list of credentials must contain at maximum 1 element.
	 * If the user is not known or does not allow any authenticator, returns an empty list.
	 * 
	 * @param userName the user name (may be <code>null</code>, but must match if specified)
	 * @param credentialId the credential ID (must match the results)
	 * @return the list of authenticators allowed for the given userName and credential ID, or an empty list.
	 */
	Future<List<Authenticator>> find(@Nullable String userName, @Nullable String credentialId);

	/**
	 * Persists a new credential, bound by its user name (may be <code>null</code>) and credential ID
	 * (cannot be <code>null</code>)
	 * @param authenticator the new credential to persist
	 * @return a future of nothing
	 */
	Future<Void> storeCredential(Authenticator authenticator);

  /**
   * Updates a credential counter, as identified by its user name (may be <code>null</code>) and credential ID
   * (cannot be <code>null</code>).
   * @param userName the user name (may be <code>null</code>, but must match if specified)
   * @param credentialId the credential ID (cannot be <code>null</code>, must match)
   * @param counter the new counter to persist
   * @return a future of nothing
   */
  Future<Void> updateCounter(Authenticator authenticator);
}
