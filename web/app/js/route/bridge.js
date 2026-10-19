// The page's side of the wallet's requests. The core blocks in its worker on each one, so each is
// answered here: through the mixnet while Nym is on, trying again through a fresh tunnel and the
// next gateway when one fails, and only after that asking the user. A request goes direct only
// when Nym is off or the user has said so for it.

import { slot } from "./slot.js";
import { consent } from "./consent.js";
import { route } from "../state/route.js";

const TRIES = 3;
const BUDGET_MS = 150_000;

export function bridge(tunnel, redraw) {
  return (port) => {
    // The wallet calls in which the user chose to stay on Nym: the rest of that call's requests
    // fail at once, so the screen says so, and the next call tries Nym again. In a call where Nym
    // has already failed past its retries, a request tries it once more before asking.
    const stayed = new Set();
    const failed = new Set();

    async function carry({ turn, method, url, headers, body }) {
      if (!route.nym) return { kind: slot.DIRECT };
      if (stayed.has(turn)) return { kind: slot.REFUSED };
      const started = Date.now();
      const tries = failed.has(turn) ? 1 : TRIES;
      for (let i = 0; i < tries && Date.now() - started < BUDGET_MS; i++) {
        try {
          const reply = await tunnel.fetch({ method, url, headers, body });
          redraw();
          return { kind: slot.REPLY, status: reply.status, bytes: reply.bytes };
        } catch {
          tunnel.reset();
          redraw();
          if (!route.nym) return { kind: slot.DIRECT };
        }
      }
      failed.add(turn);
      const choice = await consent(new URL(url).host);
      if (choice === "stay") {
        stayed.add(turn);
        return { kind: slot.REFUSED };
      }
      if (choice === "session") {
        route.nym = false;
        tunnel.stop();
        redraw();
      }
      return { kind: slot.DIRECT };
    }

    port.onmessage = async ({ data }) => {
      const answer = await carry(data).catch(() => ({ kind: slot.REFUSED }));
      slot.answer(data.buffer, answer);
    };
  };
}
