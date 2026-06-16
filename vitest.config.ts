import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    env: {
      DATABASE_URL:
        "postgresql://tectec:tectec@localhost:5432/tecteccheck",
      REDIS_URL: "redis://localhost:6379",
    },
  },
});
