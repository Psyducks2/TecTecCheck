import axios from "axios";
import chalk, { type ChalkInstance } from "chalk";
import { env } from "../../config/env";
import type { Severity } from "../../scanner/types";

const SEVERITY_COLORS: Record<Severity, ChalkInstance> = {
  LOW: chalk.blue,
  MEDIUM: chalk.yellow,
  HIGH: chalk.red,
  CRITICAL: chalk.bgRed.white,
};

interface Vulnerability {
  type: string;
  severity: Severity;
  description: string;
  evidence?: string;
  module: string;
}

interface SiteIdentification {
  summary: string;
  evidence: string;
}

interface ScanReport {
  scanId: string;
  url: string;
  status: string;
  startedAt: string | null;
  finishedAt: string | null;
  identification: SiteIdentification | null;
  vulnerabilities: Vulnerability[];
}

export async function runReportCommand(scanId: string): Promise<void> {
  try {
    const response = await axios.get(
      `http://localhost:${env.port}/api/scan/${scanId}/report`
    );
    const report = response.data as ScanReport;

    console.log(chalk.bold("\n=== TecTecCheck Report ==="));
    console.log(`Alvo:   ${chalk.cyan(report.url)}`);
    console.log(`Status: ${chalk.green(report.status)}`);
    console.log(`ID:     ${report.scanId}`);

    if (report.identification) {
      console.log(chalk.bold("\n--- Identificação do Site ---"));

      const summaryParts = report.identification.summary.split(" | ");
      for (const part of summaryParts) {
        const [label, ...rest] = part.split(": ");
        if (rest.length > 0) {
          console.log(`  ${chalk.gray(label + ":")} ${rest.join(": ")}`);
        } else {
          console.log(`  ${part}`);
        }
      }

      if (report.identification.evidence) {
        console.log(chalk.bold("\n--- Headers HTTP (curl -I style) ---\n"));
        const lines = report.identification.evidence.split("\n");
        for (const line of lines) {
          if (line.startsWith("< ")) {
            const [key, ...rest] = line.slice(2).split(": ");
            console.log(`  ${chalk.green("<")} ${chalk.cyan(key + ":")} ${rest.join(": ")}`);
          } else if (line.startsWith("---")) {
            console.log(chalk.gray(`\n  ${line}`));
          } else if (line.trim()) {
            console.log(`  ${chalk.yellow(line)}`);
          }
        }
      }
    }

    if (report.vulnerabilities.length === 0) {
      console.log(chalk.green("\n✓ Nenhuma vulnerabilidade encontrada."));
      return;
    }

    console.log(
      chalk.bold(
        `\nVulnerabilidades encontradas (${report.vulnerabilities.length}):\n`
      )
    );

    for (const vuln of report.vulnerabilities) {
      const color = SEVERITY_COLORS[vuln.severity];
      console.log(`${color(`[${vuln.severity}]`)} ${chalk.bold(vuln.type)}`);
      console.log(`  Módulo:  ${vuln.module}`);
      console.log(`  Detalhe: ${vuln.description}`);
      if (vuln.evidence) {
        console.log(`  Evidência: ${chalk.gray(vuln.evidence)}`);
      }
      console.log();
    }
  } catch (err: unknown) {
    if (axios.isAxiosError(err) && err.response?.status === 404) {
      console.error(chalk.red(`Scan '${scanId}' não encontrado.`));
    } else {
      console.error(chalk.red("Erro ao buscar relatório. API está rodando?"));
    }
    process.exit(1);
  }
}
