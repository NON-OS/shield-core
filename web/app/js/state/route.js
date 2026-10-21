// How the wallet's requests leave the page. Nym is on whenever the page opens. Turning it off, in
// Settings or in answer to the prompt, holds until the page is closed and is never stored, so the
// next visit starts on Nym again.

export const route = {
  nym: true,
  // What the tunnel last did: "idle" before the first request, then "connecting", "ready" or
  // "unreachable".
  tunnel: "idle",
  gateway: "",
  // The request travelling now, for the status line: its host, size, start and try.
  activity: null,
};
