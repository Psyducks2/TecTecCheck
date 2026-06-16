import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScanForm } from "./ScanForm";

describe("ScanForm", () => {
  it("chama onSubmit com a URL digitada", async () => {
    const onSubmit = vi.fn();
    render(<ScanForm onSubmit={onSubmit} busy={false} />);
    await userEvent.type(
      screen.getByPlaceholderText(/https:\/\//),
      "https://example.com"
    );
    await userEvent.click(screen.getByRole("button", { name: /escanear/i }));
    expect(onSubmit).toHaveBeenCalledWith("https://example.com");
  });

  it("desabilita o botão quando busy", () => {
    render(<ScanForm onSubmit={vi.fn()} busy={true} />);
    expect(screen.getByRole("button")).toBeDisabled();
  });
});
