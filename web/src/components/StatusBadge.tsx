import type { ScanStatus } from "../types";

const LABELS: Record<ScanStatus, string> = {
  PENDING: "Na fila",
  RUNNING: "Analisando",
  COMPLETED: "Concluído",
  FAILED: "Falhou",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`badge ${status}`}>{LABELS[status]}</span>;
}
