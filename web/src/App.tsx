import { useEffect, useState } from "react";
import "./styles.css";
import { ScanForm } from "./components/ScanForm";
import { StatusBadge } from "./components/StatusBadge";
import { SeverityGroup } from "./components/SeverityGroup";
import { HealthBanner } from "./components/HealthBanner";
import { ConfigForm, DEFAULT_CONFIG } from "./components/ConfigForm";
import { useScanPolling } from "./hooks/useScanPolling";
import { groupBySeverity, SEVERITY_ORDER } from "./severity";
import { getHealth } from "./api";
import type { Health, ScanConfig, ScanReport } from "./types";

type Tab = "scanner" | "resultados" | "configuracoes" | "sistema";

function downloadBlob(content: string, mime: string, filename: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportJson(report: ScanReport) {
  downloadBlob(
    JSON.stringify(report, null, 2),
    "application/json",
    `tecteccheck-${report.scanId}.json`
  );
}

function exportCsv(report: ScanReport) {
  const header = "severity,type,module,description,evidence\n";
  const rows = report.vulnerabilities
    .map(
      (v) =>
        `"${v.severity}","${v.type}","${v.module}","${v.description.replace(/"/g, '""')}","${(v.evidence ?? "").replace(/"/g, '""')}"`
    )
    .join("\n");
  downloadBlob(
    header + rows,
    "text/csv",
    `tecteccheck-${report.scanId}.csv`
  );
}

export default function App() {
  const { report, error, busy, start } = useScanPolling();
  const [health, setHealth] = useState<Health | "unreachable" | null>(null);
  const [tab, setTab] = useState<Tab>("scanner");
  const [scanConfig, setScanConfig] = useState<ScanConfig>(DEFAULT_CONFIG);

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

  useEffect(() => {
    if (report?.status === "COMPLETED" || report?.status === "FAILED") {
      setTab("resultados");
    }
  }, [report?.status]);

  const groups = report ? groupBySeverity(report.vulnerabilities) : [];
  const totalFindings = report?.vulnerabilities.length ?? 0;
  const criticalCount =
    report?.vulnerabilities.filter((v) => v.severity === "CRITICAL").length ?? 0;

  const healthStatus =
    health === null
      ? "loading"
      : health === "unreachable"
        ? "down"
        : health.status === "ok"
          ? "ok"
          : "warn";

  const healthLabel =
    health === null
      ? "Verificando…"
      : health === "unreachable"
        ? "API inacessível"
        : health.status === "ok"
          ? "Sistema online"
          : "Serviço degradado";

  const showGlobalBanner =
    health !== null &&
    (health === "unreachable" || health.status !== "ok");

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-logo">
          <div className="app-logo-icon">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span className="app-logo-text">TecTecCheck</span>
        </div>
        <div className="health-dot">
          <div className={`health-dot-indicator ${healthStatus}`} />
          <span>{healthLabel}</span>
        </div>
      </header>

      {showGlobalBanner && <HealthBanner health={health} />}

      <nav className="tabs" role="tablist" aria-label="Navegação principal">
        <button
          className={`tab-btn ${tab === "scanner" ? "active" : ""}`}
          onClick={() => setTab("scanner")}
          role="tab"
          aria-selected={tab === "scanner"}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          Scanner
        </button>

        <button
          className={`tab-btn ${tab === "resultados" ? "active" : ""}`}
          onClick={() => setTab("resultados")}
          role="tab"
          aria-selected={tab === "resultados"}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 11l3 3L22 4" />
            <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
          </svg>
          Resultados
          {report && totalFindings > 0 && (
            <span className={`tab-badge ${criticalCount > 0 ? "" : "warn"}`}>
              {totalFindings}
            </span>
          )}
          {report && totalFindings === 0 && report.status === "COMPLETED" && (
            <span className="tab-badge ok">✓</span>
          )}
        </button>

        <button
          className={`tab-btn ${tab === "configuracoes" ? "active" : ""}`}
          onClick={() => setTab("configuracoes")}
          role="tab"
          aria-selected={tab === "configuracoes"}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
          </svg>
          Configurações
        </button>

        <button
          className={`tab-btn ${tab === "sistema" ? "active" : ""}`}
          onClick={() => setTab("sistema")}
          role="tab"
          aria-selected={tab === "sistema"}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="3" width="20" height="14" rx="2" />
            <path d="M8 21h8M12 17v4" />
          </svg>
          Sistema
        </button>
      </nav>

      {/* ── Scanner Tab ── */}
      {tab === "scanner" && (
        <div className="scanner-panel">
          <div>
            <h1 className="scanner-headline">Análise de Segurança Web</h1>
            <p className="scanner-sub">
              Insira a URL do alvo para iniciar o escaneamento de vulnerabilidades.
            </p>
          </div>

          <ScanForm onSubmit={(url) => start(url, scanConfig)} busy={busy} />

          {error && (
            <div className="error-banner" role="alert">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              {error}
            </div>
          )}

          {busy && report && (
            <div className="scan-progress" role="status" aria-live="polite">
              <div className="scan-progress-header">
                <div className="scan-progress-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                  </svg>
                </div>
                <div className="scan-progress-info">
                  <div className="scan-progress-label">
                    {report.status === "PENDING" ? "Na fila…" : "Escaneando…"}
                  </div>
                  <div className="scan-progress-url">{report.url}</div>
                </div>
                <StatusBadge status={report.status} />
              </div>
              <div className="progress-bar">
                <div className="progress-bar-fill" />
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Resultados Tab ── */}
      {tab === "resultados" && (
        <div>
          {!report ? (
            <div className="results-empty">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.35-4.35" />
              </svg>
              <p>Nenhum escaneamento realizado ainda.</p>
              <p style={{ fontSize: "0.8125rem" }}>
                Vá para <strong>Scanner</strong> e insira uma URL.
              </p>
            </div>
          ) : (
            <>
              <div className="results-header">
                <div className="results-target">
                  <div className="results-target-label">Alvo</div>
                  <div className="results-target-url">{report.url}</div>
                </div>
                <StatusBadge status={report.status} />
              </div>

              {totalFindings > 0 && (
                <div className="severity-summary">
                  {SEVERITY_ORDER.map((sev) => {
                    const count = report.vulnerabilities.filter(
                      (v) => v.severity === sev
                    ).length;
                    if (!count) return null;
                    return (
                      <div key={sev} className={`sev-chip ${sev}`}>
                        <div className="sev-chip-dot" />
                        {sev}: {count}
                      </div>
                    );
                  })}
                </div>
              )}

              {report.status === "COMPLETED" && totalFindings === 0 && (
                <div className="clean-result">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                    <polyline points="22 4 12 14.01 9 11.01" />
                  </svg>
                  Nenhuma vulnerabilidade encontrada.
                </div>
              )}

              {report.status === "COMPLETED" && (
                <div className="export-actions">
                  <button className="export-btn" onClick={() => exportJson(report)} type="button">
                    <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                      <polyline points="7 10 12 15 17 10" />
                      <line x1="12" y1="15" x2="12" y2="3" />
                    </svg>
                    Exportar JSON
                  </button>
                  <button className="export-btn" onClick={() => exportCsv(report)} type="button">
                    <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                      <polyline points="7 10 12 15 17 10" />
                      <line x1="12" y1="15" x2="12" y2="3" />
                    </svg>
                    Exportar CSV
                  </button>
                </div>
              )}

              {groups.map((group) => (
                <SeverityGroup key={group.severity} group={group} />
              ))}
            </>
          )}
        </div>
      )}

      {/* ── Configurações Tab ── */}
      {tab === "configuracoes" && (
        <ConfigForm config={scanConfig} onChange={setScanConfig} />
      )}

      {/* ── Sistema Tab ── */}
      {tab === "sistema" && (
        <div>
          <p className="sistema-section-title">Status dos serviços</p>
          <div className="sistema-grid">
            <SistemaCard
              label="API"
              status={
                health === null
                  ? "loading"
                  : health === "unreachable"
                    ? "down"
                    : "ok"
              }
              text={
                health === null
                  ? "Verificando…"
                  : health === "unreachable"
                    ? "Inacessível"
                    : "Online"
              }
            />
            <SistemaCard
              label="PostgreSQL"
              status={
                health === null
                  ? "loading"
                  : health === "unreachable" || !health.checks.db
                    ? "down"
                    : "ok"
              }
              text={
                health === null
                  ? "Verificando…"
                  : health === "unreachable"
                    ? "Inacessível"
                    : health.checks.db
                      ? "Conectado"
                      : "Desconectado"
              }
            />
            <SistemaCard
              label="Redis"
              status={
                health === null
                  ? "loading"
                  : health === "unreachable" || !health.checks.redis
                    ? "down"
                    : "ok"
              }
              text={
                health === null
                  ? "Verificando…"
                  : health === "unreachable"
                    ? "Inacessível"
                    : health.checks.redis
                      ? "Conectado"
                      : "Desconectado"
              }
            />
          </div>

          {health !== null &&
            health !== "unreachable" &&
            health.status !== "ok" && <HealthBanner health={health} />}
        </div>
      )}
    </div>
  );
}

function SistemaCard({
  label,
  status,
  text,
}: {
  label: string;
  status: "ok" | "down" | "loading";
  text: string;
}) {
  return (
    <div
      className={`sistema-card ${status === "ok" ? "ok-card" : status === "down" ? "down-card" : ""}`}
    >
      <div className="sistema-card-label">{label}</div>
      <div className={`sistema-card-status status-${status}`}>
        <div className="dot" />
        {text}
      </div>
    </div>
  );
}
