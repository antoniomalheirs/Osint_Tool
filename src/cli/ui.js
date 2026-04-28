import boxen from 'boxen';
import chalk from 'chalk';
import gradient from 'gradient-string';

/**
 * Exibe o banner principal com efeito gradiente premium
 */
export function showBanner() {
  const ascii = `
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   ▄██████▄    ▄████████  ▄█  ███▄▄▄▄       ███           ║
  ║  ███    ███  ███    ███ ███  ███▀▀▀██▄ ▀█████████▄       ║
  ║  ███    ███  ███    █▀  ███▌ ███   ███    ▀███▀▀██       ║
  ║  ███    ███  ███        ███▌ ███   ███     ███   ▀       ║
  ║  ███    ███ ▀███████████ ███▌ ███   ███     ███           ║
  ║  ███    ███          ███ ███  ███   ███     ███           ║
  ║  ███    ███    ▄█    ███ ███  ███   ███     ███           ║
  ║   ▀██████▀   ▀████████▀  █▀   ▀█   █▀     ▄████▀        ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
  `;

  // Aplicamos um gradiente cyber-punk
  const cyberGradient = gradient(['#00ffff', '#ff00ff', '#8a2be2']);
  console.log(cyberGradient.multiline(ascii));
  
  console.log(chalk.yellow.bold(`       🔍  H U N T E R  —  OSINT Tool v2.0`));
  console.log(chalk.gray(`       Professional Cyber Intelligence Gatherer\n`));
}

/**
 * Cria um painel estilo "Dossiê" enquadrado para o resumo de uma entidade
 */
export function createDossierPanel(title, content, type = 'info') {
  let borderColor = 'cyan';
  if (type === 'success') borderColor = 'green';
  if (type === 'warning') borderColor = 'yellow';
  if (type === 'error') borderColor = 'red';
  if (type === 'magenta') borderColor = 'magenta';

  return boxen(content, {
    title: chalk.bold[borderColor](` [ ${title} ] `),
    titleAlignment: 'center',
    padding: 1,
    margin: 1,
    borderStyle: 'round',
    borderColor: borderColor,
  });
}

/**
 * Exibe uma mensagem de erro fatal enquadrada para não estourar o console com stack traces
 */
export function showFatalError(title, message) {
  console.log(boxen(chalk.white(message), {
    title: chalk.bold.white.bgRed(` ❌ FATAL ERROR: ${title} `),
    padding: 1,
    margin: 1,
    borderStyle: 'double',
    borderColor: 'red'
  }));
}

/**
 * Exibe um alerta simples
 */
export function showWarning(message) {
  console.log(boxen(chalk.yellow(message), {
    padding: { top: 0, bottom: 0, left: 1, right: 1 },
    borderStyle: 'round',
    borderColor: 'yellow'
  }));
}
