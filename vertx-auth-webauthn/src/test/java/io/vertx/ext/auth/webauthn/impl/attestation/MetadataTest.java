package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.file.FileSystem;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class MetadataTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void loadStatements() {
    FileSystem fs = rule.vertx()
      .fileSystem();

    Metadata metadata = new Metadata(rule.vertx());

    for (String f : fs.readDirBlocking("metadataStatements")) {
      metadata.loadMetadata(new JsonObject(fs.readFileBlocking(f)));
    }
  }
}
