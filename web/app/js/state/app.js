// What the page shows and holds: the screen, the network, the last failure, and the handles to
// the wallet worker and storage. Every change goes through `show`, which draws the screen again
// and moves focus to its heading, so a screen reader hears each new screen.

import { failureText } from "../text/failure.js";

export const app = {
  version: "",
  screen: "opening",
  params: {},
  network: "sepolia",
  failure: null,
  wallet: null,
  store: null,
  proving: null,
  draw: () => {},

  show(screen, params = {}) {
    this.screen = screen;
    this.params = params;
    this.failure = null;
    this.draw();
  },

  fail(error) {
    this.failure = error?.kind ? failureText(error) : String(error?.message ?? error);
    this.draw();
  },

  clear() {
    this.failure = null;
    this.draw();
  },

  /** Run `work`, and show what refused it in the failure banner. */
  async run(work) {
    try {
      return await work();
    } catch (e) {
      this.fail(e);
      return undefined;
    }
  },

  call(method, ...args) {
    return this.wallet.call(method, ...args);
  },
};
