import coreWebVitals from "eslint-config-next/core-web-vitals";

export default [
  ...coreWebVitals,
  {
    rules: {
      // Pre-existing patterns in the codebase that are not new regressions;
      // the react-compiler lint rules are stricter than what the codebase was
      // authored against.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/refs": "warn",
      "react-hooks/rules-of-hooks": "warn",
      "react/no-unescaped-entities": "warn",
    },
  },
];
