// The zip is read back by the system's own unzip, so its layout is checked by something else.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zip } from "./zip.js";

test("a stored zip unpacks to the same bytes", async () => {
  const files = [
    ["spend.proof", Uint8Array.from({ length: 1000 }, (_, i) => i & 0xff)],
    ["blob0.bin", new Uint8Array([1, 2, 3])],
  ];
  const dir = mkdtempSync(join(tmpdir(), "zip-"));
  writeFileSync(join(dir, "out.zip"), Buffer.from(await zip(files).arrayBuffer()));
  execFileSync("python3", ["-I", "-m", "zipfile", "-e", join(dir, "out.zip"), join(dir, "x")]);
  for (const [name, data] of files)
    assert.deepEqual(new Uint8Array(readFileSync(join(dir, "x", name))), data);
});
