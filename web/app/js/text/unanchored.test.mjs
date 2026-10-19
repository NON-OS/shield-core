import { test } from "node:test";
import assert from "node:assert/strict";
import { unanchored } from "./unanchored.js";

const balances = [{ coin: "eth", spendableText: "0.04975" }];

test("a refusal the shown balance covers is told as a root not yet listed", () => {
  assert.match(unanchored({ kind: "Insufficient" }, balances, "eth", "0.01", "0.003"), /registry/);
});

test("a refusal the balance does not cover, or another failure, is left as it is", () => {
  assert.equal(unanchored({ kind: "Insufficient" }, balances, "eth", "0.1"), null);
  assert.equal(unanchored({ kind: "Insufficient" }, balances, "eth", "0.0469", "0.003"), null);
  assert.equal(unanchored({ kind: "Insufficient" }, balances, "nox", "1000"), null);
  assert.equal(unanchored({ kind: "TooSoon" }, balances, "eth", "0.01"), null);
});
