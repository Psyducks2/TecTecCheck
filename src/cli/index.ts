#!/usr/bin/env node
import "dotenv/config";
import { Command } from "commander";
import chalk from "chalk";
import { runScanCommand } from "./commands/scan.command";
import { runReportCommand } from "./commands/report.command";

const program = new Command();

program
  .name("tecteccheck")
  .description(
    chalk.cyan("TecTecCheck") + " — Scanner de vulnerabilidades web público"
  )
  .version("0.1.0");

program
  .command("scan <url>")
  .description("Inicia um novo scan de vulnerabilidades para a URL informada")
  .action(async (url: string) => {
    await runScanCommand(url);
  });

program
  .command("report <scanId>")
  .description("Exibe o relatório de um scan concluído")
  .action(async (scanId: string) => {
    await runReportCommand(scanId);
  });

program.parse(process.argv);
