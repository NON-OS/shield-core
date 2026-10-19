// A spend proved here and not yet settled. The apps resume theirs from the lander's hand-off; the
// web has no lander, so it keeps what the screens need to offer the settlement again: the paths
// of the hand-off files, the defaults given up, and the settlement once it is sent. None of it is
// secret, and the files themselves stay in the wallet's sealed storage.

const KEY = "spend-in-flight";

export const inFlight = {
  get: (app) => app.store.meta(KEY),
  set: (app, spend) => app.store.setMeta(KEY, spend),
  clear: (app) => app.store.setMeta(KEY, null),
};
