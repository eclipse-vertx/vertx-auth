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
	 * (cannot be <code>null</code>, must be unique).
	 * 
	 * If attempting to store a credential with a <code>credId</code> that is not unique, you should return
	 * a failed <code>Future</code>.
   * 
   * If attempting to store a credential with a <code>userName</code> that already exists, you should 
   * first make sure that the current user is already logged in under the same <code>userName</code>, because
   * this will in practice add a new credential to identify the existing user, so this must be restricted
   * to the already existing user, otherwise you will allow anyone to gain access to existing users.
   * 
   * If attempting to store a credential with a <code>userName</code> that already exists, and the current
   * user is not logged in, or the logged in user does not have the same <code>userName</code>, you should
   * return a failed <code>Future</code>.
	 * 
	 * @param authenticator the new credential to persist
	 * @return a future of nothing, or a failed future if the <code>credId</code> already exists, or if the
	 * <code>userName</code> already exists and does not represent the currently logged in user.
	 */
	Future<Void> storeCredential(Authenticator authenticator);

  /**
   * Updates a previously stored credential counter, as identified by its user name (may be <code>null</code>) and credential ID
   * (cannot be <code>null</code>, must be unique).
   * @param authenticator the credential to update
   * @return a future of nothing
   */
  Future<Void> updateCounter(Authenticator authenticator);
}
