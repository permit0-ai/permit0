const { defineConfig } = require("vitest/config");

module.exports = defineConfig({
  test: {
    include: ["__tests__/**/*.test.{js,ts,mjs}"],
  },
});
