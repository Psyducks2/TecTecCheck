import type { Health } from "../types";

export function HealthBanner({ health }: { health: Health | null }) {
  if (!health) return null;
  if (health.status === "ok") {
    return <div className="banner up">Backend OK — banco e fila conectados.</div>;
  }
  const down = [
    !health.checks.db && "PostgreSQL",
    !health.checks.redis && "Redis",
  ].filter(Boolean);
  return (
    <div className="banner down">
      Mau funcionamento: {down.join(" e ")} indisponível. Rode{" "}
      <code>npm run docker:up</code>.
    </div>
  );
}
