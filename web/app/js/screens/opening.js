import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";

export function opening() {
  return frame(
    { number: "01", title: "NØNOS", backdrop: "welcome" },
    h("p", { class: "lead", role: "status" }, "Opening"),
  );
}
