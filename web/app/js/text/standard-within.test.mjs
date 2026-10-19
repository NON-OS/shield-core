import { test } from "node:test";
import assert from "node:assert/strict";
import { standardWithin } from "./standard-within.js";

test("a deposit note sends the largest size that leaves room for the fee", () => {
  assert.equal(standardWithin("0.0199", "0.006", "0.01"), "0.01");
  assert.equal(standardWithin("0.04975", "0.006", "0.01"), "0.02");
  assert.equal(standardWithin("4,975", "2,400", "1000"), "2000");
});

test("a note too small for the smallest size and the fee sends nothing", () => {
  assert.equal(standardWithin("0.00995", "0.006", "0.01"), null);
  assert.equal(standardWithin("0.0102", "0.006", "0.01"), null);
  assert.equal(standardWithin("0.016", "0.006", "0.01"), "0.01");
});
