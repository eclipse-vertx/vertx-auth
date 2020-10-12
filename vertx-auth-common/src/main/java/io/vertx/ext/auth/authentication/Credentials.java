/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.authentication;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;

/**
 * Abstract representation of a Credentials object. All implementations of this interface will define the
 * required types and parameters for the specific implementation.
 *
 * @author Paulo Lopes
 */
@VertxGen(concrete = false)
public interface Credentials {
  /**
   * Implementors should override this method to perform validation. An argument is allowed to
   * allow custom validation, for example, when given a configuration property, a specific
   * property may be allowed to be null.
   *
   * @param arg optional argument or null.
   * @param <V> the generic type of the argument
   * @throws CredentialValidationException when the validation fails
   */
  default <V> void checkValid(V arg) throws CredentialValidationException {
  }

  /**
   * Simple interop to downcast back to JSON for backwards compatibility.
   *
   * @return JSON representation of this credential.
   */
  JsonObject toJson();

  /**
   * Applies the HTTP Authorization challenge to this Credential instance. The internal state can change to reflect
   * the extra properties the challenge conveys.
   *
   * See <a href="https://tools.ietf.org/html/rfc7235">https://tools.ietf.org/html/rfc7235</a> for more information.
   *
   * @param challenge the challenge is the {@code WWW-Authenticate} header response from a 401 request.
   *                  Null challenges are allowed, and in this case, no verification will be performed, however it is
   *                  up to the implementation to permit this.

   * @return fluent self.
   * @throws CredentialValidationException if the challenge cannot be applicable.
   */
  @Fluent
  default Credentials applyHttpChallenge(String challenge) throws CredentialValidationException {
    if (challenge != null) {
      throw new CredentialValidationException("This implementation can't check the challenge: " + challenge);
    }

    return this;
  }

  /**
   * Encodes this credential as an HTTP Authorization <a href="https://tools.ietf.org/html/rfc7235">https://tools.ietf.org/html/rfc7235</a>.
   *
   * @param method The http method this response is responding.
   * @param uri The http uri this response is responding.
   * @param nc The client internal counter.
   * @param vertx The vertx instance.
   *
   * @throws UnsupportedOperationException when the the credential object cannot be converted to a HTTP Authorization.
   * @return HTTP header including scheme.
   */
  default String toHttpAuthorization(Vertx vertx, HttpMethod method, String uri, int nc) {
    throw new UnsupportedOperationException(getClass().getName() + " cannot be converted to a HTTP Authorization header");
  }
}
