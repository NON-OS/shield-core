import { h } from "./h.js";

/**
 * How far the newest unspent note is from blending in, in the apps' one line: notes still to be
 * added to the pool and the hours still to pass. Shown only after a read of the pool.
 */
export function meter(chain) {
  if (!chain) return null;
  const parts = [];
  if (chain.waitLeaves > 0) parts.push(`${chain.waitLeaves} more notes in the pool`);
  if (chain.waitMinutes > 0) parts.push(`about ${Math.ceil(chain.waitMinutes / 60)} hours`);
  const line = parts.length
    ? `Ready to spend privately after ${parts.join(" and ")}. Spending sooner can be linked by timing.`
    : "Ready to spend privately.";
  return h("p", { class: "lead", role: "status" }, line);
}
