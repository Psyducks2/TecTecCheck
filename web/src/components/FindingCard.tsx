import type { Vulnerability } from "../types";

export function FindingCard({ vuln }: { vuln: Vulnerability }) {
  return (
    <div className={`finding ${vuln.severity}`}>
      <strong>{vuln.type}</strong>
      <div className="meta">módulo: {vuln.module}</div>
      <div>{vuln.description}</div>
      {vuln.evidence && <div className="evidence">{vuln.evidence}</div>}
    </div>
  );
}
