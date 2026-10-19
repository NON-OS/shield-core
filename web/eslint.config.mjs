// Lint for the page, its workers and the tools that build and test it.

import js from "@eslint/js";
import globals from "globals";

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: { ...globals.browser, ...globals.worker, ...globals.node },
    },
    rules: {
      "no-console": ["error", { allow: ["error", "log"] }],
    },
  },
  { ignores: ["node_modules/**"] },
];
