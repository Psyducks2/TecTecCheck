import type { SeverityGroupData } from "../severity";
import { FindingCard } from "./FindingCard";

export function SeverityGroup({ group }: { group: SeverityGroupData }) {
  if (group.items.length === 0) return null;
  return (
    <div className="sev-group">
      <div className="sev-group-header">
        <span className={`sev-group-label ${group.severity}`}>{group.severity}</span>
        <span className="sev-group-count">
          {group.items.length} {group.items.length === 1 ? "ocorrência" : "ocorrências"}
        </span>
        <div className="sev-group-line" />
      </div>
      {group.items.map((vuln) => (
        <FindingCard key={vuln.id} vuln={vuln} />
      ))}
    </div>
  );
}
