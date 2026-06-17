import { useState, useCallback } from "react";
import type { ModuleName, ScanConfig } from "../types";

interface HeaderPair {
  key: string;
  value: string;
}

const ALL_MODULES: { id: ModuleName; name: string; desc: string }[] = [
  { id: "recon", name: "Reconhecimento", desc: "Verifica acessibilidade do alvo. Recomendado." },
  { id: "identification", name: "Identificação", desc: "Mapeia servidor, CMS e metadados." },
  { id: "headers", name: "Headers HTTP", desc: "Audita headers de segurança ausentes." },
  { id: "fuzzer", name: "Fuzzer", desc: "Descobre diretórios e arquivos expostos." },
  { id: "fingerprint", name: "Fingerprint", desc: "Detecta tecnologias por assinaturas." },
];

export const DEFAULT_CONFIG: ScanConfig = {
  headers: {},
  excludePaths: [],
  maxRps: 10,
  modules: ALL_MODULES.map((m) => m.id),
};

interface Props {
  config: ScanConfig;
  onChange: (config: ScanConfig) => void;
}

export function ConfigForm({ config, onChange }: Props) {
  const [headerPairs, setHeaderPairs] = useState<HeaderPair[]>(() =>
    Object.entries(config.headers ?? {}).map(([key, value]) => ({ key, value }))
  );

  const syncHeaders = useCallback(
    (pairs: HeaderPair[]) => {
      setHeaderPairs(pairs);
      const headers: Record<string, string> = {};
      for (const { key, value } of pairs) {
        if (key.trim()) headers[key.trim()] = value;
      }
      onChange({ ...config, headers });
    },
    [config, onChange]
  );

  const addHeader = () =>
    syncHeaders([...headerPairs, { key: "", value: "" }]);

  const removeHeader = (i: number) =>
    syncHeaders(headerPairs.filter((_, idx) => idx !== i));

  const updateHeader = (i: number, field: "key" | "value", val: string) =>
    syncHeaders(
      headerPairs.map((p, idx) => (idx === i ? { ...p, [field]: val } : p))
    );

  const enabledModules = config.modules ?? ALL_MODULES.map((m) => m.id);
  const blacklistText = (config.excludePaths ?? []).join("\n");

  const handleReset = () => {
    setHeaderPairs([]);
    onChange({ ...DEFAULT_CONFIG });
  };

  return (
    <div className="config-panel">
      {/* Custom Headers */}
      <div className="config-section">
        <div>
          <p className="config-section-title">Autenticação — Headers Personalizados</p>
          <p className="config-section-desc">
            Tokens Bearer, cookies ou qualquer header HTTP para escanear rotas protegidas.
          </p>
        </div>
        <div className="header-pairs">
          {headerPairs.map((pair, i) => (
            <div key={i} className="header-pair">
              <input
                type="text"
                value={pair.key}
                onChange={(e) => updateHeader(i, "key", e.target.value)}
                placeholder="Authorization"
                aria-label="Nome do header"
              />
              <input
                type="text"
                value={pair.value}
                onChange={(e) => updateHeader(i, "value", e.target.value)}
                placeholder="Bearer eyJhbGci…"
                aria-label="Valor do header"
              />
              <button
                className="icon-btn"
                onClick={() => removeHeader(i)}
                type="button"
                aria-label="Remover header"
              >
                <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5" strokeLinecap="round">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
          ))}
          <button
            className="icon-btn add"
            onClick={addHeader}
            type="button"
            style={{ width: "auto", padding: "0.375rem 0.75rem", gap: "0.375rem", fontSize: "0.8125rem" }}
          >
            <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5" strokeLinecap="round">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Adicionar header
          </button>
        </div>
      </div>

      {/* Blacklist */}
      <div className="config-section">
        <div>
          <p className="config-section-title">Exclusão de Rotas (Blacklist)</p>
          <p className="config-section-desc">
            Um caminho por linha. Suporta regex: <code>/^\/admin/i</code>. O fuzzer ignorará essas rotas.
          </p>
        </div>
        <textarea
          className="config-textarea"
          placeholder={"/logout\n/delete\n/^\\/\\.git/"}
          value={blacklistText}
          onChange={(e) =>
            onChange({
              ...config,
              excludePaths: e.target.value
                .split("\n")
                .map((l) => l.trim())
                .filter(Boolean),
            })
          }
          rows={4}
          aria-label="Rotas a excluir do fuzzer"
        />
      </div>

      {/* Throttle */}
      <div className="config-section">
        <div>
          <p className="config-section-title">Throttling — Limite de Requisições</p>
          <p className="config-section-desc">
            Requisições por segundo enviadas ao alvo. Valores baixos são mais gentis com o servidor.
          </p>
        </div>
        <div className="rps-control">
          <input
            type="range"
            className="rps-slider"
            min={1}
            max={50}
            value={config.maxRps ?? 10}
            onChange={(e) =>
              onChange({ ...config, maxRps: Number(e.target.value) })
            }
            aria-label="Requisições por segundo"
          />
          <span className="rps-value">{config.maxRps ?? 10} rps</span>
        </div>
        <div className="rps-labels">
          <span>Gentil (1)</span>
          <span>Padrão (10)</span>
          <span>Agressivo (50)</span>
        </div>
      </div>

      {/* Module selection */}
      <div className="config-section">
        <div>
          <p className="config-section-title">Módulos do Scanner</p>
          <p className="config-section-desc">Selecione quais módulos serão executados no scan.</p>
        </div>
        <div className="module-grid">
          {ALL_MODULES.map((mod) => {
            const checked = enabledModules.includes(mod.id);
            return (
              <label key={mod.id} className={`module-item ${checked ? "checked" : ""}`}>
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={(e) => {
                    const next = e.target.checked
                      ? ([...enabledModules, mod.id] as ModuleName[])
                      : enabledModules.filter((m) => m !== mod.id);
                    onChange({ ...config, modules: next });
                  }}
                />
                <div className="module-item-info">
                  <div className="module-item-name">{mod.name}</div>
                  <div className="module-item-desc">{mod.desc}</div>
                </div>
              </label>
            );
          })}
        </div>
      </div>

      <div className="config-reset-row">
        <button className="config-reset-btn" onClick={handleReset} type="button">
          Restaurar padrões
        </button>
      </div>
    </div>
  );
}
