import type { Vulnerability } from "../types";

export function FindingCard({ vuln }: { vuln: Vulnerability }) {
  return (
    <div className={`finding ${vuln.severity}`}>
      <div className="finding-header">
        <span className="finding-type">{vuln.type}</span>
      </div>
      <div className="finding-module">
        módulo: <span>{vuln.module}</span>
      </div>
      <div className="finding-desc">{vuln.description}</div>
      {vuln.evidence && <div className="finding-evidence">{vuln.evidence}</div>}
    </div>
  );
}
