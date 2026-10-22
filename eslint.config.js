import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "packages/netcheck/certs/**",
      "coverage/**",
      "fixtures/**",
      "apps/safari/Shared (Extension)/Resources/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        console: "readonly",
        process: "readonly",
        URL: "readonly",
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { "argsIgnorePattern": "^_", "varsIgnorePattern": "^_" },
      ],
    },
  },
  {
    files: ["apps/extension/**/*.ts"],
    languageOptions: {
      globals: {
        chrome: "readonly",
        document: "readonly",
        HTMLInputElement: "readonly",
      },
    },
  },
);
