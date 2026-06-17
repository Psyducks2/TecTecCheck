import type { Health } from "../types";

export function HealthBanner({ health }: { health: Health | "unreachable" | null }) {
  if (!health) return null;

  if (health === "unreachable") {
    return (
      <div className="health-banner-full down" role="alert">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
        Backend inacessível — a API não está respondendo. Rode <code>npm run dev</code>.
      </div>
    );
  }

  if (health.status === "ok") return null;

  const down = [
    !health.checks.db && "PostgreSQL",
    !health.checks.redis && "Redis",
  ].filter(Boolean);

  return (
    <div className="health-banner-full warn" role="alert">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
      Mau funcionamento: {down.join(" e ")} indisponível. Rode <code>npm run docker:up</code>.
    </div>
  );
}
