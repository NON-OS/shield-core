// One read of the pool at a time. A read asked for while one runs, from the shield's button or the
// read every five minutes, joins the one running rather than queueing a second full read behind
// it, which over the mixnet would double the wait.

import { app } from "./app.js";

let running = null;

export function readPool() {
  running ??= app.call("syncChain").finally(() => {
    running = null;
  });
  return running;
}
