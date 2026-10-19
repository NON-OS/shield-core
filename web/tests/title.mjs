// A screen's heading as the bar shows it: its two-digit number, then the title.
export const title = (name) =>
  new RegExp(`^\\d\\d\\s+${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i");
