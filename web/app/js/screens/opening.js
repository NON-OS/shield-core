import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";

export function opening() {
  return frame("01", "NØNOS", h("p", { class: "lead", role: "status" }, "Opening"));
}
