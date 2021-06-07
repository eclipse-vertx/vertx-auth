/*
 * Copyright 2019 Red Hat, Inc.
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
package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

import java.security.cert.CertificateException;

/**
 * Factory interface for creating FIDO2 MetaDataService.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface MetaDataService {

  /**
   * Fetches the FIDO2 TOC for the given URL and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @param url the url to the TOC
   * @param handler the async handler to process the response
   * @return fluent self
   */
  @Fluent
  default MetaDataService fetchTOC(String url, Handler<AsyncResult<Boolean>> handler) {
    fetchTOC(url).onComplete(handler);
    return this;
  }

  /**
   * Fetches the FIDO2 MDS3 TOC and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @param handler the async handler to process the response
   * @return fluent self
   */
  @Fluent
  default MetaDataService fetchTOC(Handler<AsyncResult<Boolean>> handler) {
    fetchTOC().onComplete(handler);
    return this;
  }

  /**
   * Fetches the FIDO2 TOC for the given URL and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @param url the url to the TOC
   * @return future result of the operation
   */
  Future<Boolean> fetchTOC(String url);

  /**
   * Fetches the FIDO2 MDS3 TOC and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @return future result of the operation
   */
  default Future<Boolean> fetchTOC() {
    return fetchTOC("https://mds.fidoalliance.org");
  }

  /**
   * Manually feed a Meta Data Statement to the service.
   *
   * @param statement the json statement
   * @return fluent self
   */
  @Fluent
  MetaDataService addStatement(JsonObject statement);

  /**
   * Clears all loaded statements, both from the TOC and manually inserted.
   * The flush operation will not cancel any in-flight TOC download/processing.
   *
   * @return fluent self
   */
  @Fluent
  MetaDataService flush();

  /**
   * Verify the metadata for a given authenticator. The MDS will lookup the metadata by the AAGUID. If no AAGUID is
   * known, the result will be {@code null}.
   *
   * When a statement is found, the statement will be used to verify the certificate chain. A failure during this
   * verification will throw a {@link RuntimeException}.
   *
   * @param authenticator authenticator to verify
   * @return an MDS statement for this authenticator or {@code null}.
   * @throws RuntimeException if the verification fails.
   */
  @Nullable
  JsonObject verify(Authenticator authenticator);
}
