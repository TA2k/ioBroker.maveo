import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: [".eslintrc.js", "node_modules/**", "admin/words.js"],
  },
  js.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        ...globals.node,
        ...globals.mocha,
        ...globals.es2022,
      },
    },
    rules: {
      indent: ["error", 2, { SwitchCase: 1 }],
      "no-console": "off",
      "no-var": "error",
      "no-trailing-spaces": "error",
      "prefer-const": "error",
      quotes: [
        "error",
        "double",
        {
          avoidEscape: true,
          allowTemplateLiterals: true,
        },
      ],
      semi: ["error", "always"],
    },
  },
  {
    files: ["**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.node,
      },
    },
  },
];
