import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusBadge } from "./StatusBadge";

describe("StatusBadge", () => {
  it("mostra o rótulo PT correto para cada status", () => {
    const cases: Array<[Parameters<typeof StatusBadge>[0]["status"], string]> = [
      ["PENDING", "Na fila"],
      ["RUNNING", "Analisando"],
      ["COMPLETED", "Concluído"],
      ["FAILED", "Falhou"],
    ];
    for (const [status, label] of cases) {
      const { unmount } = render(<StatusBadge status={status} />);
      expect(screen.getByText(label)).toBeInTheDocument();
      unmount();
    }
  });

  it("aplica a classe do status no badge", () => {
    const { container } = render(<StatusBadge status="RUNNING" />);
    expect(container.querySelector(".badge.RUNNING")).not.toBeNull();
  });
});
