import type { SeverityGroupData } from "../severity";
import { FindingCard } from "./FindingCard";

export function SeverityGroup({ group }: { group: SeverityGroupData }) {
  if (group.items.length === 0) return null;
  return (
    <div className="sev-group">
      <h3>
        {group.severity} ({group.items.length})
      </h3>
      {group.items.map((vuln) => (
        <FindingCard key={vuln.id} vuln={vuln} />
      ))}
    </div>
  );
}
