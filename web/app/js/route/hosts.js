// The hosts the mixnet client may reach, and nothing else: Nym's directory, which lists the nodes
// and the exits, and a pinned set of entry gateways, one of which carries every request for a
// session. The release writes these into the Content Security Policy, so the page cannot open a
// gateway that is not here. Each gateway is an operator other than the rest, in a country other
// than the rest, and was listed with wss and a performance of 0.99 or more when it was pinned;
// web/scripts/check-gateways.mjs says which still are.

export const nymHosts = {
  api: ["validator.nymtech.net", "nym-frontdoor.global.ssl.fastly.net", "cdn1.media-platform.net"],
  gateways: [
    { id: "FPS6BJYSYgDHm5SLtsouCQGA1LCjBgusCKFjXJFgPTL5", host: "nym-exit.ca05.bhsysmx.st" },
    {
      id: "AG8jRRMBEYgDTW628fapkTS9VsNW5K3JsGDSZAUoMuDC",
      host: "nym-gateway-03.swisscryptonodes.ch",
    },
    { id: "2RmEBKhQHsqvw5sjnnt2Bhpy96MPDUkbfWkT6r2RWNCR", host: "node-04.privacymeow.fyi" },
    { id: "GZ8AmCWvUosQcotiR9SbiYkoJb22RKPTSkcze7NKhbaM", host: "stake-09.turquoiselab.io" },
    { id: "9Z5dGUqLHVSgYFZ8G4gEwiQFYyjhnMHn7JiZDadbuMmZ", host: "exit-nl-06.aurorasky.org" },
    { id: "9bzMzVX8bfAzE1roQPTbX2jzXjnt7TScpepzdhf2J7KT", host: "nym-exit.fi-1.spectredao.net" },
    { id: "3m81xM7eeXHrnyicf7utUBWHMu2TgmBeWFZVte2wgRS4", host: "exit10.nym.works" },
    { id: "HVQ4F162KaumT5WHJrTdJ3LycgtETMjna1GLNmAGHuhR", host: "nym-exit.node4.techpundit.sbs" },
  ],
  port: 9001,
};
