-- Dedup Targets: for each url group, keep the oldest Target.
-- First, reassign Scans from duplicate Targets to the canonical (oldest) Target.
UPDATE "Scan" s
SET "targetId" = canonical.id
FROM (
  SELECT DISTINCT ON (url) id, url
  FROM "Target"
  ORDER BY url, "createdAt" ASC
) AS canonical
JOIN "Target" dup ON dup.url = canonical.url AND dup.id != canonical.id
WHERE s."targetId" = dup.id;

-- Delete the duplicate Target records (now safe, no Scans reference them)
DELETE FROM "Target"
WHERE id NOT IN (
  SELECT DISTINCT ON (url) id
  FROM "Target"
  ORDER BY url, "createdAt" ASC
);

-- Add unique constraint on url
ALTER TABLE "Target" ADD CONSTRAINT "Target_url_key" UNIQUE ("url");
