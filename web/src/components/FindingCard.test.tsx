import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingCard } from "./FindingCard";
import type { Vulnerability } from "../types";

const vuln: Vulnerability = {
  id: "v1",
  module: "headers",
  type: "MISSING_HSTS",
  severity: "HIGH",
  description: "Header HSTS ausente",
  evidence: "Strict-Transport-Security não encontrado",
};

describe("FindingCard", () => {
  it("mostra tipo, módulo, descrição e evidência", () => {
    render(<FindingCard vuln={vuln} />);
    expect(screen.getByText("MISSING_HSTS")).toBeInTheDocument();
    expect(screen.getByText(/headers/)).toBeInTheDocument();
    expect(screen.getByText("Header HSTS ausente")).toBeInTheDocument();
    expect(
      screen.getByText("Strict-Transport-Security não encontrado")
    ).toBeInTheDocument();
  });

  it("aplica a classe da severidade no container", () => {
    const { container } = render(<FindingCard vuln={vuln} />);
    expect(container.querySelector(".finding.HIGH")).not.toBeNull();
  });

  it("omite a evidência quando evidence é null", () => {
    const { container } = render(<FindingCard vuln={{ ...vuln, evidence: null }} />);
    expect(container.querySelector(".evidence")).toBeNull();
  });
});
