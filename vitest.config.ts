import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    exclude: ["**/node_modules/**", "web/**"],
    env: {
      DATABASE_URL:
        "postgresql://tectec:tectec@localhost:5432/tecteccheck",
      REDIS_URL: "redis://localhost:6379",
    },
  },
});
