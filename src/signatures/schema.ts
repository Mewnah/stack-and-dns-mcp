/**
 * Zod schema for the signature database. The JSON file is validated once at
 * startup so a malformed entry fails fast instead of silently never matching.
 */

import { z } from "zod";

export const SignatureSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, "id must be kebab-case"),
  name: z.string().min(1),
  category: z.string().min(1),
  website: z.string().optional(),
  confidence: z.number().int().min(1).max(100).default(100),
  html: z.array(z.string().min(1)).default([]),
  scripts: z.array(z.string().min(1)).default([]),
  headers: z.record(z.string().min(1), z.string()).default({}),
  cookies: z.array(z.string().min(1)).default([]),
  meta: z.record(z.string().min(1), z.string()).default({}),
  implies: z.array(z.string().min(1)).default([]),
  excludes: z.array(z.string().min(1)).default([])
});

export const SignatureDatabaseSchema = z.object({
  version: z.string().min(1),
  categories: z.record(z.string().min(1), z.string().min(1)),
  signatures: z.array(SignatureSchema).min(1)
});

export type Signature = z.infer<typeof SignatureSchema>;
export type SignatureDatabase = z.infer<typeof SignatureDatabaseSchema>;
