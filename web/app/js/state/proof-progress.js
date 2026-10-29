// A proof's progress as the prover reports it. The prover names each phase as it finishes; between
// two reports the bar moves on this device's own timings of its earlier proofs, and it never passes
// the end of the running phase before the prover says that phase is done.

const KEY = "proof-phases";
const ORDER = [
  "request",
  "blinding",
  "region",
  "products",
  "periodic",
  "composition",
  "composition-tree",
  "deep",
  "fri",
  "queries",
  "verified",
];
// Where each phase ends, as a share of the time from the request checked to the proof verified, as
// the prover measured it on eight cores, until this device has its own.
const PRIOR = {
  request: 0,
  blinding: 0.02,
  region: 0.11,
  products: 0.2,
  periodic: 0.22,
  composition: 0.4,
  "composition-tree": 0.44,
  deep: 0.54,
  fri: 0.93,
  queries: 0.96,
  verified: 1,
};

/** The steps a person sees, each ending with the named phase. */
export const STEPS = [
  { label: "Prepare the spend", until: "blinding" },
  { label: "Commit to the notes", until: "periodic" },
  { label: "Check every constraint", until: "deep" },
  { label: "Fold and grind", until: "fri" },
  { label: "Verify it here", until: "verified" },
];

/** A spend reads the pool's state through the network before the prover starts. */
const NETWORK = { label: "Read the pool's state", until: "request", network: true };

let live = null;
let learned = null;

/** Read what earlier proofs on this device took, and the Measure timing if there is one. */
export async function loadPace(store, measured) {
  learned =
    (await store.meta(KEY)) ?? (measured ? { seconds: measured.seconds, ends: null } : null);
}

/** A proof starts now, after a read of the pool's state when `network` is set. */
export function begin({ network = false } = {}) {
  live = { start: Date.now(), marks: {}, steps: network ? [NETWORK, ...STEPS] : STEPS };
}

/** The steps of the running proof, or of a Measure run when none is running. */
export function steps() {
  return live?.steps ?? STEPS;
}

/** The prover finished `phase`. */
export function mark(phase) {
  if (live && ORDER.includes(phase)) live.marks[phase] = Date.now();
}

/** The proof finished. Its timings become part of this device's pace, weighted with the last. */
export async function finish(store) {
  const { request: zero, verified: end } = live?.marks ?? {};
  if (!zero || !end || end <= zero) return;
  const seconds = (end - zero) / 1000;
  const blend = (a, b) => (a == null ? b : (a + b) / 2);
  const share = (p) => (live.marks[p] ? (live.marks[p] - zero) / 1000 / seconds : PRIOR[p]);
  learned = {
    seconds: blend(learned?.seconds, seconds),
    ends: Object.fromEntries(ORDER.map((p) => [p, blend(learned?.ends?.[p], share(p))])),
  };
  live = null;
  await store.setMeta(KEY, learned);
}

/**
 * Where the running proof is: the share done, the seconds left when they can be told, and the
 * time each step took. A spend reads the pool's state before the prover starts, so the clock for
 * the pace starts at the prover's first report.
 */
export function estimate(now = Date.now()) {
  if (!live) return null;
  const ends = learned?.ends ?? PRIOR;
  const elapsed = (now - live.start) / 1000;
  const zero = live.marks.request;
  const known = learned?.seconds ?? null;
  if (!zero) return { share: 0, left: known, elapsed, steps: took(live) };
  const into = (now - zero) / 1000;
  const last = ORDER.filter((p) => live.marks[p]).at(-1);
  const next = ORDER[ORDER.indexOf(last) + 1] ?? "verified";
  const [f0, f1] = [ends[last], ends[next]];
  // The proof's length: this device's pace, corrected by how this proof has kept to it so far.
  const seen = f0 > 0 ? (live.marks[last] - zero) / 1000 / f0 : null;
  const total = known && seen ? (1 - f0) * known + f0 * seen : (known ?? seen);
  if (!total) return { share: f0, left: null, elapsed, steps: took(live) };
  const part = Math.min(0.97, Math.max(0, (into - total * f0) / (total * (f1 - f0))));
  const share = f0 + (f1 - f0) * part;
  const left = Math.max(total * (1 - f1), total - into);
  return { share, left, elapsed, steps: took(live) };
}

function took(run) {
  let from = run.start;
  return run.steps.map((s) => {
    const at = run.marks[s.until];
    const took = at ? (at - from) / 1000 : null;
    if (at) from = at;
    return { ...s, took };
  });
}
