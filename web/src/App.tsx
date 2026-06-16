import { useEffect, useState } from "react";
import "./styles.css";
import { ScanForm } from "./components/ScanForm";
import { StatusBadge } from "./components/StatusBadge";
import { SeverityGroup } from "./components/SeverityGroup";
import { HealthBanner } from "./components/HealthBanner";
import { useScanPolling } from "./hooks/useScanPolling";
import { groupBySeverity } from "./severity";
import { getHealth } from "./api";
import type { Health } from "./types";

export default function App() {
  const { report, error, busy, start } = useScanPolling();
  const [health, setHealth] = useState<Health | "unreachable" | null>(null);

  useEffect(() => {
    let active = true;
    const check = () =>
      getHealth()
        .then((h) => active && setHealth(h))
        .catch(() => active && setHealth("unreachable"));
    check();
    const id = setInterval(check, 5000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  const groups = report ? groupBySeverity(report.vulnerabilities) : [];
  const hasFindings = report && report.vulnerabilities.length > 0;

  return (
    <div className="app">
      <h1>TecTecCheck</h1>
      <p className="subtitle">Scanner de vulnerabilidades web</p>

      <HealthBanner health={health} />
      <ScanForm onSubmit={start} busy={busy} />

      {error && <p className="error">{error}</p>}

      {report && (
        <section>
          <p>
            Alvo: <strong>{report.url}</strong> <StatusBadge status={report.status} />
          </p>
          {report.status === "COMPLETED" && !hasFindings && (
            <p>Nenhuma vulnerabilidade encontrada.</p>
          )}
          {groups.map((group) => (
            <SeverityGroup key={group.severity} group={group} />
          ))}
        </section>
      )}
    </div>
  );
}
