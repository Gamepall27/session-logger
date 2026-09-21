import test from "node:test";
import assert from "node:assert/strict";
import { severitiesAtOrAbove } from "./server.js";

test("severity filters include the selected level and every higher level", () => {
  assert.deepEqual(severitiesAtOrAbove("info"), ["info", "low", "medium", "high", "critical"]);
  assert.deepEqual(severitiesAtOrAbove("low"), ["low", "medium", "high", "critical"]);
  assert.deepEqual(severitiesAtOrAbove("medium"), ["medium", "high", "critical"]);
  assert.deepEqual(severitiesAtOrAbove("high"), ["high", "critical"]);
  assert.deepEqual(severitiesAtOrAbove("critical"), ["critical"]);
  assert.equal(severitiesAtOrAbove("invalid"), null);
});
