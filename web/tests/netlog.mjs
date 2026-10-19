// Every host Chromium opened a request, a socket or a WebSocket to, from its net log, with the
// first time each was named, in Unix milliseconds. The net log covers the whole browser, so the
// page's workers are in it as well as the page.

import { readFileSync } from "node:fs";

export function netHosts(file) {
  let text = readFileSync(file, "utf8").trim();
  // A browser closed without finishing the log leaves the events array open.
  if (!text.endsWith("}")) text = `${text.replace(/,\s*$/, "")}]}`;
  const log = JSON.parse(text);
  const offset = Number(log.constants.timeTickOffset);
  const first = new Map();
  const note = (value, time) => {
    if (typeof value !== "string") return;
    const match = value.match(/^(?:[a-z]+:\/\/)?([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(?:\/|$)/i);
    if (!match) return;
    const host = match[1].toLowerCase();
    if (!first.has(host) || first.get(host) > time) first.set(host, time);
  };
  for (const event of log.events) {
    const time = Number(event.time) + offset;
    for (const key of ["url", "host", "host_and_port", "server", "origin"])
      note(event.params?.[key], time);
  }
  return first;
}
