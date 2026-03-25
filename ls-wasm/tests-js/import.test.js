import test from "node:test";
import assert from "node:assert/strict";

import { createWorker } from "../index.js";

test("exports createWorker", () => {
  assert.equal(typeof createWorker, "function");
});
