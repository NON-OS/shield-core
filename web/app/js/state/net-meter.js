// The requests the page carries through the mixnet for the wallet, timed, so a screen that waits on
// the network can say how many have gone and how long the last one took. Nothing here leaves the
// page, and it holds no address, body or reply.

let marks = [];
let open = 0;

/** Count from zero, for a screen starting its own wait. */
export function resetMeter() {
  marks = [];
}

/** One request starts; call the returned function once it ends. */
export function metered() {
  const start = Date.now();
  open += 1;
  return (ok) => {
    open -= 1;
    marks.push({ start, end: Date.now(), ok });
  };
}

/** How many requests ended since the reset, how long the last took, and whether one is out now. */
export function meter() {
  const last = marks.at(-1);
  return {
    done: marks.length,
    lastSeconds: last ? (last.end - last.start) / 1000 : null,
    waiting: open > 0,
  };
}
