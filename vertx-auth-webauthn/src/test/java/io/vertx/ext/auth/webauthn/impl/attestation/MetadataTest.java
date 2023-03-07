package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.file.FileSystem;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataEntry;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class MetadataTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void loadStatements() {
    FileSystem fs = rule.vertx()
      .fileSystem();

    MetaData metadata = new MetaData(rule.vertx(), new WebAuthnOptions());

    for (String f : fs.readDirBlocking("metadataStatements")) {
      metadata.loadMetadata(new MetaDataEntry(new JsonObject(fs.readFileBlocking(f))));
    }
  }
}
