import "dotenv/config";

function required(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing required env var: ${key}`);
  return value;
}

export const env = {
  databaseUrl: required("DATABASE_URL"),
  redisUrl: required("REDIS_URL"),
  port: parseInt(process.env["PORT"] ?? "3000", 10),
  fuzzerConcurrency: parseInt(process.env["FUZZER_CONCURRENCY"] ?? "5", 10),
  fuzzerTimeoutMs: parseInt(process.env["FUZZER_TIMEOUT_MS"] ?? "3000", 10),
};
