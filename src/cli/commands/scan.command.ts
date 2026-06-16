import axios from "axios";
import chalk from "chalk";
import ora from "ora";
import { env } from "../../config/env";

export async function runScanCommand(url: string): Promise<void> {
  const spinner = ora(`Iniciando scan para ${chalk.cyan(url)}...`).start();

  try {
    const response = await axios.post(`http://localhost:${env.port}/api/scan`, {
      url,
    });
    const { scanId } = response.data as { scanId: string };

    spinner.succeed(`Scan criado! ID: ${chalk.green(scanId)}`);
    console.log(chalk.yellow("\nAguardando processamento pelo worker..."));
    console.log(`\nPara ver o relatório quando concluído, execute:`);
    console.log(chalk.cyan(`  tecteccheck report ${scanId}`));
  } catch (err: unknown) {
    spinner.fail("Falha ao criar scan.");
    if (axios.isAxiosError(err) && err.response?.data) {
      console.error(
        chalk.red("Erro:"),
        (err.response.data as { error: string }).error
      );
    } else {
      console.error(
        chalk.red("Erro:"),
        "API não está rodando. Execute: npm run dev"
      );
    }
    process.exit(1);
  }
}
