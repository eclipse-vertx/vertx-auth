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

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;

/**
 * Abstract representation of a Credentials object. All implementations of this interface will define the
 * required types and parameters for the specific implementation.
 *
 * @author Paulo Lopes
 */
@VertxGen
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
   * <p>
   * See <a href="https://tools.ietf.org/html/rfc7235">https://tools.ietf.org/html/rfc7235</a> for more information.
   *
   * @param challenge the challenge is the {@code WWW-Authenticate} header response from a 401 request.
   *                  Null challenges are allowed, and in this case, no verification will be performed, however it is
   *                  up to the implementation to permit this.
   * @param method    The http method this response is responding.
   * @param uri       The http uri this response is responding.
   * @param nc        The client internal counter (optional).
   * @param cnonce    The client internal nonce (optional).
   * @return fluent self.
   * @throws CredentialValidationException if the challenge cannot be applicable.
   */
  default Credentials applyHttpChallenge(String challenge, HttpMethod method, String uri, Integer nc, String cnonce) throws CredentialValidationException {
    if (challenge != null) {
      throw new CredentialValidationException("This implementation can't handle HTTP Authentication");
    }

    return this;
  }

  /**
   * Applies the HTTP Authorization challenge to this Credential instance. The internal state can change to reflect
   * the extra properties the challenge conveys.
   * <p>
   * See <a href="https://tools.ietf.org/html/rfc7235">https://tools.ietf.org/html/rfc7235</a> for more information.
   *
   * @param challenge the challenge is the {@code WWW-Authenticate} header response from a 401 request.
   *                  Null challenges are allowed, and in this case, no verification will be performed, however it is
   *                  up to the implementation to permit this.
   * @param method    The http method this response is responding.
   * @param uri       The http uri this response is responding.
   * @return fluent self.
   * @throws CredentialValidationException if the challenge cannot be applicable.
   */
  default Credentials applyHttpChallenge(String challenge, HttpMethod method, String uri) throws CredentialValidationException {
    return applyHttpChallenge(challenge, method, uri, null, null);
  }

  /**
   * Applies the HTTP Authorization challenge to this Credential instance. The internal state can change to reflect
   * the extra properties the challenge conveys.
   * <p>
   * See <a href="https://tools.ietf.org/html/rfc7235">https://tools.ietf.org/html/rfc7235</a> for more information.
   *
   * @param challenge the challenge is the {@code WWW-Authenticate} header response from a 401 request.
   *                  Null challenges are allowed, and in this case, no verification will be performed, however it is
   *                  up to the implementation to permit this.
   * @return fluent self.
   * @throws CredentialValidationException if the challenge cannot be applicable.
   */
  default Credentials applyHttpChallenge(String challenge) throws CredentialValidationException {
    return applyHttpChallenge(challenge, null, null, null, null);
  }

  /**
   * Encodes this credential as an HTTP Authorization <a href="https://tools.ietf.org/html/rfc7235">https://tools.ietf.org/html/rfc7235</a>.
   * <p>
   * Calls to this method, expect that {@link #applyHttpChallenge(String, HttpMethod, String, Integer, String)} has
   * been prior executed. For some Authentication schemes, this isn't a requirement but doing so ensures that the
   * object is on the right state.
   *
   * @return HTTP header including scheme.
   * @throws UnsupportedOperationException when the the credential object cannot be converted to a HTTP Authorization.
   */
  default String toHttpAuthorization() {
    throw new UnsupportedOperationException(getClass().getName() + " cannot be converted to a HTTP Authorization");
  }
}
