import { useState, type FormEvent } from "react";

interface Props {
  onSubmit: (url: string) => void;
  busy: boolean;
}

export function ScanForm({ onSubmit, busy }: Props) {
  const [url, setUrl] = useState("");

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (trimmed) onSubmit(trimmed);
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://exemplo.com"
        aria-label="URL do alvo"
      />
      <button type="submit" disabled={busy}>
        {busy ? "Escaneando…" : "Escanear"}
      </button>
    </form>
  );
}
