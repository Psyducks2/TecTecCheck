import { z } from "zod";

export const scanRequestSchema = z.object({
  url: z
    .string()
    .url("URL inválida")
    .refine(
      (url) => url.startsWith("http://") || url.startsWith("https://"),
      "URL deve usar protocolo HTTP ou HTTPS"
    ),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;
