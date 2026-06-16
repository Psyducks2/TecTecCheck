import { z } from "zod";

const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^0\.0\.0\.0$/,
];

function isPrivateHost(url: string): boolean {
  try {
    const { hostname } = new URL(url);
    return PRIVATE_IP_PATTERNS.some((p) => p.test(hostname));
  } catch {
    return true;
  }
}

export const scanRequestSchema = z.object({
  url: z
    .string()
    .url("URL inválida")
    .refine(
      (url) => url.startsWith("http://") || url.startsWith("https://"),
      "URL deve usar protocolo HTTP ou HTTPS"
    )
    .refine(
      (url) => !isPrivateHost(url),
      "URL não pode apontar para endereços privados ou loopback"
    ),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;
