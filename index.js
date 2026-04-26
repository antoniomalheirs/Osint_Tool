#!/usr/bin/env node

/**
 * OSINT Hunter v2.0 — CLI Entry Point
 * Professional Cyber Intelligence Tool
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import readline from 'node:readline/promises';

import { getConfig } from './src/config.js';
import { initLogger } from './src/logger.js';
import { initNetwork } from './src/network.js';
import { correlateResults } from './src/correlator.js';
import { searchUsername, getFoundResults } from './src/engine.js';
import { searchEmail } from './src/emailSearch.js';
import { initDB, saveInvestigation, getHistory } from './src/database.js';
import {
  printBanner,
  printUsernameResults,
  printEmailResults,
  exportJSON,
  exportCSV,
  exportTXT,
  exportHTML,
} from './src/reporter.js';
import {
  isEmail,
  generateUsernameVariations,
  formatDuration,
} from './src/utils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sitesPath = path.join(__dirname, 'data', 'sites.json');
const sites = JSON.parse(fs.readFileSync(sitesPath, 'utf-8'));

const program = new Command();

program
  .name('osint-hunter')
  .description(chalk.cyan('🔍 OSINT Hunter v2.0 — Rastreamento profissional de usernames e e-mails'))
  .version('2.0.0');

// ═══════════════════════════════════════════
// Helper para a ação de Hunt
// ═══════════════════════════════════════════
async function executeHunt(target, options) {
  const config = getConfig();
  const log = initLogger({ verbose: options.verbose, level: config.logging.level });
  
  const timeout = options.timeout ? parseInt(options.timeout, 10) : config.network.timeout;
  initNetwork({ timeout, proxy: options.proxy, maxRetries: config.network.maxRetries });
  
  initDB(); // Inicializa o banco se configurado

  printBanner();
  const startTime = Date.now();
  let usernameResults = null;
  let emailResults = null;
  let finalIntel = null;

  log.info(`Iniciando investigação. Alvo: ${target}`);
  if (options.proxy) log.info(`Utilizando proxy: ${options.proxy}`);

  const includeNSFW = options.nsfw || config.search.includeNSFW;
  if (includeNSFW) log.info(`Modo NSFW: ATIVADO`);

  // ── Se o alvo é um e-mail ──
  if (isEmail(target)) {
    console.log(chalk.white.bold('  🎯 Alvo detectado como: ') + chalk.magenta.bold('E-MAIL'));
    console.log(chalk.gray(`  📧 ${target}\n`));

    const emailSpinner = ora({ text: chalk.yellow(' Buscando informações do e-mail...'), spinner: 'dots12', color: 'magenta' }).start();
    emailResults = await searchEmail(target);
    emailSpinner.succeed(chalk.green(' Busca por e-mail concluída!'));
    printEmailResults(target, emailResults);

    if (!options.emailOnly) {
      const variations = generateUsernameVariations(target);
      console.log(chalk.cyan.bold('  🔄 Variações de username geradas a partir do e-mail:'));
      variations.forEach(v => console.log(chalk.gray(`     → ${v}`)));
      console.log('');

      for (const variant of variations) {
        let sitesToSearch = sites;
        if (!includeNSFW) sitesToSearch = sitesToSearch.filter(s => !s.isNSFW);
        if (options.category) sitesToSearch = sitesToSearch.filter(s => (s.category||'').toLowerCase().includes(options.category.toLowerCase()));

        const spinner = ora({ text: chalk.yellow(` Buscando username "${variant}" em ${sitesToSearch.length} plataformas...`), spinner: 'dots12', color: 'cyan' }).start();

        let completed = 0;
        const results = await searchUsername(variant, sites, {
          includeNSFW,
          filterCategory: options.category,
          onResult: (result) => {
            completed++;
            const icon = result.skipped ? chalk.gray('~') : result.found ? chalk.green('✓') : result.error ? chalk.yellow('!') : chalk.red('✗');
            spinner.text = chalk.yellow(` [${completed}/${sitesToSearch.length}] `) + icon + chalk.gray(` ${result.site}`);
          }
        });

        const found = getFoundResults(results);
        spinner.succeed(chalk.green(` "${variant}" — ${found.length} perfis encontrados`));
        printUsernameResults(variant, results);

        const intel = correlateResults(variant, results, emailResults || []);
        console.log(chalk.magenta.bold('\n  🧠 INTELIGÊNCIA E CORRELAÇÃO'));
        console.log(chalk.white(`     Score de Presença: `) + (intel.presenceScore > 50 ? chalk.red(intel.presenceScore) : chalk.green(intel.presenceScore)) + '/100');
        console.log(chalk.white(`     Score de Risco:    `) + (intel.finalRiskScore >= 75 ? chalk.red(intel.finalRiskScore) : chalk.yellow(intel.finalRiskScore)) + '/100');
        console.log(chalk.white(`     Conf. Intel:       `) + chalk.cyan(`${intel.intelligenceConfidence}/100`));
        console.log(chalk.white(`     Nível de Risco:    `) + chalk.yellow(intel.riskLevel));
        console.log(chalk.white(`     Perfil:            `) + chalk.cyan(intel.profileType));
        if (intel.metadataIntel.inferredNames.length > 0) {
          console.log(chalk.white(`     Nomes Inferidos:   `) + chalk.gray(intel.metadataIntel.inferredNames.slice(0, 3).join(', ')));
        }
        if (intel.behaviorIntel.flags.length > 0) {
          console.log(chalk.white(`     Flags Intel:       `) + chalk.red(intel.behaviorIntel.flags.map(f => `${f.type}(${f.severity})`).join(', ')));
        }
        if (intel.evidenceTrail.length > 0) {
          console.log(chalk.white(`     Evidências:        `) + chalk.gray(intel.evidenceTrail[0]));
        }
        console.log('');

        if (variant === variations[0]) {
          usernameResults = results;
          finalIntel = intel;
        }
      }
    }
  } else {
    // ── Se o alvo é um username ──
    console.log(chalk.white.bold('  🎯 Alvo detectado como: ') + chalk.cyan.bold('USERNAME'));
    console.log(chalk.gray(`  👤 ${target}\n`));

    if (!options.emailOnly) {
      let sitesToSearch = sites;
      if (!includeNSFW) sitesToSearch = sitesToSearch.filter(s => !s.isNSFW);
      if (options.category) sitesToSearch = sitesToSearch.filter(s => (s.category||'').toLowerCase().includes(options.category.toLowerCase()));

      const spinner = ora({ text: chalk.yellow(` Buscando "${target}" em ${sitesToSearch.length} plataformas...`), spinner: 'dots12', color: 'cyan' }).start();

      let completed = 0;
      usernameResults = await searchUsername(target, sites, {
        includeNSFW,
        filterCategory: options.category,
        onResult: (result) => {
          completed++;
          const icon = result.skipped ? chalk.gray('~') : result.found ? chalk.green('✓') : result.error ? chalk.yellow('!') : chalk.red('✗');
          spinner.text = chalk.yellow(` [${completed}/${sitesToSearch.length}] `) + icon + chalk.gray(` ${result.site}`);
        }
      });

      const found = getFoundResults(usernameResults);
      spinner.succeed(chalk.green(` Busca concluída — ${found.length} perfis encontrados em ${formatDuration(Date.now() - startTime)}`));
      printUsernameResults(target, usernameResults);

      finalIntel = correlateResults(target, usernameResults, emailResults || []);
      console.log(chalk.magenta.bold('\n  🧠 INTELIGÊNCIA E CORRELAÇÃO'));
      console.log(chalk.white(`     Score de Presença: `) + (finalIntel.presenceScore > 50 ? chalk.red(finalIntel.presenceScore) : chalk.green(finalIntel.presenceScore)) + '/100');
      console.log(chalk.white(`     Score de Risco:    `) + (finalIntel.finalRiskScore >= 75 ? chalk.red(finalIntel.finalRiskScore) : chalk.yellow(finalIntel.finalRiskScore)) + '/100');
      console.log(chalk.white(`     Conf. Intel:       `) + chalk.cyan(`${finalIntel.intelligenceConfidence}/100`));
      console.log(chalk.white(`     Nível de Risco:    `) + chalk.yellow(finalIntel.riskLevel));
      console.log(chalk.white(`     Perfil:            `) + chalk.cyan(finalIntel.profileType));
      if (finalIntel.metadataIntel.inferredNames.length > 0) {
        console.log(chalk.white(`     Nomes Inferidos:   `) + chalk.gray(finalIntel.metadataIntel.inferredNames.slice(0, 3).join(', ')));
      }
      if (finalIntel.behaviorIntel.flags.length > 0) {
        console.log(chalk.white(`     Flags Intel:       `) + chalk.red(finalIntel.behaviorIntel.flags.map(f => `${f.type}(${f.severity})`).join(', ')));
      }
      if (finalIntel.behaviorIntel.recommendations.length > 0) {
        console.log(chalk.white(`     Próx. passos:      `) + chalk.gray(finalIntel.behaviorIntel.recommendations[0]));
      }
      if (finalIntel.evidenceTrail.length > 0) {
        console.log(chalk.white(`     Evidências:        `) + chalk.gray(finalIntel.evidenceTrail[0]));
      }
      console.log('');
    }
  }

  // ── Salvar no Banco ──
  saveInvestigation(target, isEmail(target), usernameResults, emailResults, finalIntel);

  // ── Exportação ──
  const fmt = (options.export || config.search.exportFormat).toLowerCase();
  if (fmt && fmt !== 'none') {
    console.log(chalk.cyan.bold('\n  📦 EXPORTANDO RELATÓRIOS\n'));
    if (fmt === 'json' || fmt === 'all') exportJSON(target, usernameResults, emailResults);
    if (fmt === 'csv' || fmt === 'all') exportCSV(target, usernameResults);
    if (fmt === 'txt' || fmt === 'all') exportTXT(target, usernameResults, emailResults);
    if (fmt === 'html' || fmt === 'all') exportHTML(target, usernameResults, emailResults, finalIntel);
    console.log('');
  }

  console.log(chalk.gray(`  ⏱️  Tempo total: ${formatDuration(Date.now() - startTime)}\n`));
  log.info(`Investigação finalizada em ${formatDuration(Date.now() - startTime)}`);
}

// ═══════════════════════════════════════════
// Comandos CLI
// ═══════════════════════════════════════════

program
  .command('hunt')
  .description('Busca completa: username + email')
  .argument('<target>', 'Username ou e-mail para rastrear')
  .option('-e, --export <format>', 'Exportar relatório (json, csv, txt, html, all)')
  .option('-t, --timeout <ms>', 'Timeout por requisição em ms')
  .option('--no-email', 'Pular busca por e-mail (quando alvo é username)')
  .option('--email-only', 'Apenas busca por e-mail')
  .option('--nsfw', 'Incluir sites NSFW na busca (sobrescreve config)')
  .option('-c, --category <name>', 'Filtrar busca por categoria')
  .option('-p, --proxy <url>', 'Usar proxy (ex: socks5://127.0.0.1:9050)')
  .option('-v, --verbose', 'Modo verboso (exibe logs detalhados)')
  .action(executeHunt);

program
  .command('list')
  .description('Lista todas as plataformas suportadas')
  .option('--nsfw', 'Incluir sites NSFW na listagem')
  .action((options) => {
    printBanner();
    const config = getConfig();
    const includeNSFW = options.nsfw || config.search.includeNSFW;
    let displaySites = sites;
    if (!includeNSFW) displaySites = sites.filter(s => !s.isNSFW);
    
    console.log(chalk.cyan.bold(`\n  📋 Plataformas suportadas (${displaySites.length} total)\n`));
    const grouped = {};
    for (const site of displaySites) {
      const cat = site.category || 'Outros';
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(site);
    }
    for (const [category, catSites] of Object.entries(grouped).sort()) {
      console.log(chalk.yellow.bold(`\n  ▸ ${category} (${catSites.length})`));
      for (const site of catSites) {
        console.log(chalk.gray(`    • ${site.name.padEnd(25)} `) + chalk.blue((site.urlProbe || site.url).replace(/\{\}|\{username\}/g, '<user>')));
      }
    }
    console.log('');
  });

program
  .command('history')
  .description('Exibe o histórico de investigações salvas localmente')
  .option('-n, --limit <number>', 'Número de registros para exibir', '10')
  .action((options) => {
    printBanner();
    initDB();
    const records = getHistory(parseInt(options.limit, 10));
    
    if (records.length === 0) {
      console.log(chalk.yellow('\n  Nenhum histórico encontrado no banco de dados local.\n'));
      return;
    }

    console.log(chalk.cyan.bold(`\n  📚 HISTÓRICO DE INVESTIGAÇÕES (Últimas ${records.length})\n`));
    for (const r of records) {
      const typeStr = r.target_type === 'EMAIL' ? chalk.magenta('[EMAIL]') : chalk.cyan('[USER] ');
      const riskStr = r.risk_level === 'CRITICAL' ? chalk.red(r.risk_level) : r.risk_level === 'HIGH' ? chalk.yellow(r.risk_level) : chalk.green(r.risk_level);
      console.log(`  ${chalk.gray(r.timestamp)} ${typeStr} ${chalk.white.bold(r.target.padEnd(20))} | Score: ${r.presence_score} | Risco: ${riskStr}`);
    }
    console.log('');
  });

program
  .command('config')
  .description('Exibe as configurações atuais (default.yml)')
  .action(() => {
    printBanner();
    const config = getConfig();
    console.log(chalk.cyan.bold('\n  ⚙️  CONFIGURAÇÕES ATUAIS\n'));
    console.log(chalk.white(JSON.stringify(config, null, 2)));
    console.log(chalk.gray('\n  Para alterar, edite o arquivo config/default.yml\n'));
  });

program
  .command('interactive')
  .description('Inicia o modo interativo (REPL) para múltiplas buscas')
  .action(async () => {
    printBanner();
    console.log(chalk.yellow.bold('\n  🚀 MODO INTERATIVO (REPL) INICIADO'));
    console.log(chalk.gray('  Digite "exit" ou "quit" para sair.\n'));

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: chalk.cyan('osint> ')
    });

    rl.prompt();

    rl.on('line', async (line) => {
      const input = line.trim();
      if (!input) {
        rl.prompt();
        return;
      }
      if (input.toLowerCase() === 'exit' || input.toLowerCase() === 'quit') {
        console.log(chalk.gray('\nEncerrando sessão...'));
        process.exit(0);
      }

      // Parsea comando simples: "target" ou "target --nsfw"
      const args = input.split(' ');
      const target = args[0];
      const options = {
        nsfw: args.includes('--nsfw'),
        export: args.includes('--export') ? 'html' : '', // Atalho para exportar
      };

      try {
        await executeHunt(target, options);
      } catch (err) {
        console.log(chalk.red(`\nErro durante a execução: ${err.message}`));
      }

      console.log('');
      rl.prompt();
    }).on('close', () => {
      console.log(chalk.gray('\nEncerrando sessão...'));
      process.exit(0);
    });
  });

// ═══════════════════════════════════════════
program.parse();

if (!process.argv.slice(2).length) {
  printBanner();
  program.outputHelp();
}
