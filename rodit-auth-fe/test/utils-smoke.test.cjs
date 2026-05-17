"use strict";

/**
 * Node smoke tests for @rodit/rodit-auth-fe.
 *
 * The SDK is built for browser bundling (Parcel); some modules mix `require()` with
 * ESM (`services/logger.js`), so a full `require('../utils.js')` cannot run in plain
 * Node. These tests only verify declared npm deps resolve and the package layout.
 */

const { test } = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const fs = require("node:fs");

test("declared dependencies resolve in Node", () => {
  const { ulid } = require("ulid");
  assert.match(ulid(), /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/i);
  require("tweetnacl");
  require("tweetnacl-util");
  require("bs58");
  require("jwt-decode");
});

test("package entry files exist", () => {
  const root = path.join(__dirname, "..");
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  assert.strictEqual(pkg.name, "@rodit/rodit-auth-fe");
  for (const file of [pkg.main, "utils.js", "services/logger.js", "frontend/rodit_fe.js"]) {
    assert.ok(fs.existsSync(path.join(root, file)), `expected file: ${file}`);
  }
});
