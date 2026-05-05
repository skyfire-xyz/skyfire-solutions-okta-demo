import js from "@eslint/js";
import eslintPluginNext from "@next/eslint-plugin-next";
import tseslint from "typescript-eslint";

export default [
  {
    name: "project/ignores",
    ignores: [".next/**", "node_modules/**", "next-env.d.ts"],
  },

  // Base JS rules
  js.configs.recommended,

  // TypeScript rules (flat config)
  ...tseslint.configs.recommended,

  // Next.js rules (flat config)
  {
    name: "next/core-web-vitals",
    plugins: {
      "@next/next": eslintPluginNext,
    },
    rules: {
      ...eslintPluginNext.configs["core-web-vitals"].rules,
    },
  },
];
