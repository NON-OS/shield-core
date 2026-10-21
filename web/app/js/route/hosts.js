// The hosts the mixnet client may reach: Nym's directory, which lists the nodes and the exits, and
// any entry gateway it lists, on the ports gateways serve secure WebSockets on. The release writes
// these into the Content Security Policy. Which gateway a tunnel uses is read from the directory
// each time one starts (directory.js), so no release holds a list that ages.

export const nymHosts = {
  api: ["validator.nymtech.net", "nym-frontdoor.global.ssl.fastly.net", "cdn1.media-platform.net"],
  ports: [9001, 443],
};
