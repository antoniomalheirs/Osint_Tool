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
import { searchUsername, getFoundResults, retryBlockedSites, buildOperationalSummary } from './src/engine.js';
import { searchEmail } from './src/emailSearch.js';
import { searchDorks } from './src/dorkEngine.js';
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
  isFullName,
  generateUsernameVariations,
  generateNameVariations,
  formatDuration,
} from './src/utils.js';
import { createDossierPanel, showFatalError } from './src/cli/ui.js';

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
export async function executeHunt(target, options) {
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
  const retryBlocked = options.retryBlocked || config.search.retryBlocked;
  const strictOperational = options.strictOperational || config.search.strictOperational;
  const retryDelayMs = Number.isFinite(parseInt(options.retryDelay, 10))
    ? parseInt(options.retryDelay, 10)
    : (config.search.retryDelayMs || 1200);
  const retryAttempts = Number.isFinite(parseInt(options.retryAttempts, 10))
    ? parseInt(options.retryAttempts, 10)
    : (config.search.retryAttempts || 2);
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
        let results = await searchUsername(variant, sites, {
          includeNSFW,
          filterCategory: options.category,
          onResult: (result) => {
            completed++;
            const icon = result.skipped ? chalk.gray('~') : result.found ? chalk.green('✓') : result.error ? chalk.yellow('!') : chalk.red('✗');
            spinner.text = chalk.yellow(` [${completed}/${sitesToSearch.length}] `) + icon + chalk.gray(` ${result.site}`);
          }
        });
        if (retryBlocked) {
          const retryOutcome = await retryBlockedSites(variant, sites, results, {
            delayMs: retryDelayMs,
            attempts: retryAttempts,
            onResult: () => {},
          });
          results = retryOutcome.mergedResults;
          if (retryOutcome.retried > 0) {
            log.info(`Retry de bloqueados finalizado para "${variant}" (${retryOutcome.retried} plataformas).`);
          }
        }

        const found = getFoundResults(results);
        spinner.succeed(chalk.green(` "${variant}" — ${found.length} perfis encontrados`));
        printUsernameResults(variant, results);
        if (strictOperational) {
          const opSummary = buildOperationalSummary(results);
          if (opSummary.quarantined.length > 0) {
            console.log(chalk.yellow(`  🧪 Quarentena SOC/IR: ${opSummary.quarantined.length} plataforma(s) inconclusiva(s)/bloqueada(s)`));
          }
        }

        // --- DORK ENGINE (DYNAMIC SCRAPING) ---
        const dorkSpinner = ora({ text: chalk.yellow(` Vasculhando motores de busca (Dorking) por "${variant}"...`), spinner: 'dots12', color: 'cyan' }).start();
        const dorkResults = await searchDorks(variant);
        if (dorkResults.length > 0) {
          dorkSpinner.succeed(chalk.green(` Dorking concluído — ${dorkResults.length} menções dinâmicas encontradas!`));
          console.log(chalk.cyan.bold('\n  🕸️  RESULTADOS DINÂMICOS (SEARCH ENGINES)'));
          for (const dr of dorkResults) {
            const confColor = dr.confidence === 'HIGH' ? chalk.green('HIGH') : chalk.yellow('MEDIUM');
            console.log(`  ${chalk.gray('▸')} ${chalk.white(dr.domain.padEnd(20))} [${confColor}] ${chalk.blue(dr.url)}`);
          }
        } else {
          dorkSpinner.info(chalk.gray(` Dorking concluído — Nenhuma menção dinâmica adicional encontrada.`));
        }

        const intel = correlateResults(variant, results, emailResults || []);
        
        let intelStr = chalk.white(`Score de Presença: `) + (intel.presenceScore > 50 ? chalk.red(intel.presenceScore) : chalk.green(intel.presenceScore)) + '/100\n';
        intelStr += chalk.white(`Score de Risco:    `) + (intel.finalRiskScore >= 75 ? chalk.red(intel.finalRiskScore) : chalk.yellow(intel.finalRiskScore)) + '/100\n';
        intelStr += chalk.white(`Conf. Intel:       `) + chalk.cyan(`${intel.intelligenceConfidence}/100`) + '\n';
        intelStr += chalk.white(`Nível de Risco:    `) + chalk.yellow(intel.riskLevel) + '\n';
        intelStr += chalk.white(`Perfil:            `) + chalk.cyan(intel.profileType) + '\n';
        if (intel.metadataIntel.inferredNames.length > 0) {
          intelStr += chalk.white(`Nomes Inferidos:   `) + chalk.gray(intel.metadataIntel.inferredNames.slice(0, 3).join(', ')) + '\n';
        }
        if (intel.behaviorIntel.flags.length > 0) {
          intelStr += chalk.white(`Flags Intel:       `) + chalk.red(intel.behaviorIntel.flags.map(f => `${f.type}(${f.severity})`).join(', ')) + '\n';
        }
        if (intel.evidenceTrail.length > 0) {
          intelStr += chalk.white(`Evidências:        `) + chalk.gray(intel.evidenceTrail[0]) + '\n';
        }
        
        console.log('\n' + createDossierPanel('🧠 DOSSIÊ DE INTELIGÊNCIA', intelStr, 'magenta') + '\n');

        if (variant === variations[0]) {
          usernameResults = results;
          finalIntel = intel;
        }
      }
    }
  }
  // ── Se o alvo é um Nome Completo ──
  else if (isFullName(target)) {
    console.log(chalk.white.bold('  🎯 Alvo detectado como: ') + chalk.cyan.bold('NOME COMPLETO'));
    console.log(chalk.gray(`  👤 ${target}\n`));

    // DORK ENGINE DIRETO NO NOME
    const dorkSpinner = ora({ text: chalk.yellow(` Vasculhando motores de busca (Dorking) por "${target}"...`), spinner: 'dots12', color: 'cyan' }).start();
    const dorkResults = await searchDorks(target);
    if (dorkResults.length > 0) {
      dorkSpinner.succeed(chalk.green(` Dorking concluído — ${dorkResults.length} menções dinâmicas encontradas para o nome!`));
      console.log(chalk.cyan.bold('\n  🕸️  RESULTADOS DINÂMICOS (SEARCH ENGINES)'));
      for (const dr of dorkResults) {
        const confColor = dr.confidence === 'HIGH' ? chalk.green('HIGH') : chalk.yellow('MEDIUM');
        console.log(`  ${chalk.gray('▸')} ${chalk.white(dr.domain.padEnd(20))} [${confColor}] ${chalk.blue(dr.url)}`);
      }
      console.log('');
    } else {
      dorkSpinner.info(chalk.gray(` Dorking concluído — Nenhuma menção dinâmica adicional encontrada para o nome.\n`));
    }

    const variations = generateNameVariations(target);
    console.log(chalk.cyan.bold('  🔄 Variações de username geradas a partir do nome:'));
    variations.forEach(v => console.log(chalk.gray(`     → ${v}`)));
    console.log('');

    for (const variant of variations) {
      let sitesToSearch = sites;
      if (!includeNSFW) sitesToSearch = sitesToSearch.filter(s => !s.isNSFW);
      if (options.category) sitesToSearch = sitesToSearch.filter(s => (s.category||'').toLowerCase().includes(options.category.toLowerCase()));

      const spinner = ora({ text: chalk.yellow(` Buscando username "${variant}" em ${sitesToSearch.length} plataformas...`), spinner: 'dots12', color: 'cyan' }).start();

      let completed = 0;
      let results = await searchUsername(variant, sites, {
        includeNSFW,
        filterCategory: options.category,
        onResult: (result) => {
          completed++;
          const icon = result.skipped ? chalk.gray('~') : result.found ? chalk.green('✓') : result.error ? chalk.yellow('!') : chalk.red('✗');
          spinner.text = chalk.yellow(` [${completed}/${sitesToSearch.length}] `) + icon + chalk.gray(` ${result.site}`);
        }
      });
      
      if (retryBlocked) {
        const retryOutcome = await retryBlockedSites(variant, sites, results, {
          delayMs: retryDelayMs,
          attempts: retryAttempts,
          onResult: () => {},
        });
        results = retryOutcome.mergedResults;
        if (retryOutcome.retried > 0) {
          log.info(`Retry de bloqueados finalizado para "${variant}" (${retryOutcome.retried} plataformas).`);
        }
      }

      const found = getFoundResults(results);
      spinner.succeed(chalk.green(` "${variant}" — ${found.length} perfis encontrados`));
      printUsernameResults(variant, results);

      if (strictOperational) {
        const opSummary = buildOperationalSummary(results);
        if (opSummary.quarantined.length > 0) {
          console.log(chalk.yellow(`  🧪 Quarentena SOC/IR: ${opSummary.quarantined.length} plataforma(s) inconclusiva(s)/bloqueada(s)`));
        }
      }

      const intel = correlateResults(variant, results, []);
      let intelStr = chalk.white(`Score de Presença: `) + (intel.presenceScore > 50 ? chalk.red(intel.presenceScore) : chalk.green(intel.presenceScore)) + '/100\n';
      intelStr += chalk.white(`Score de Risco:    `) + (intel.finalRiskScore >= 75 ? chalk.red(intel.finalRiskScore) : chalk.yellow(intel.finalRiskScore)) + '/100\n';
      intelStr += chalk.white(`Conf. Intel:       `) + chalk.cyan(`${intel.intelligenceConfidence}/100`) + '\n';
      intelStr += chalk.white(`Nível de Risco:    `) + chalk.yellow(intel.riskLevel) + '\n';
      intelStr += chalk.white(`Perfil:            `) + chalk.cyan(intel.profileType) + '\n';
      if (intel.metadataIntel.inferredNames.length > 0) {
        intelStr += chalk.white(`Nomes Inferidos:   `) + chalk.gray(intel.metadataIntel.inferredNames.slice(0, 3).join(', ')) + '\n';
      }
      if (intel.behaviorIntel.flags.length > 0) {
        intelStr += chalk.white(`Flags Intel:       `) + chalk.red(intel.behaviorIntel.flags.map(f => `${f.type}(${f.severity})`).join(', ')) + '\n';
      }
      if (intel.evidenceTrail.length > 0) {
        intelStr += chalk.white(`Evidências:        `) + chalk.gray(intel.evidenceTrail[0]) + '\n';
      }
      console.log('\n' + createDossierPanel('🧠 DOSSIÊ DE INTELIGÊNCIA', intelStr, 'magenta') + '\n');
      
      if (variant === variations[0]) {
        usernameResults = results;
        finalIntel = intel;
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
      if (retryBlocked) {
        const retryOutcome = await retryBlockedSites(target, sites, usernameResults, {
          delayMs: retryDelayMs,
          attempts: retryAttempts,
          onResult: () => {},
        });
        usernameResults = retryOutcome.mergedResults;
        if (retryOutcome.retried > 0) {
          log.info(`Retry de bloqueados finalizado para "${target}" (${retryOutcome.retried} plataformas).`);
        }
      }

      const found = getFoundResults(usernameResults);
      spinner.succeed(chalk.green(` Busca concluída — ${found.length} perfis encontrados em ${formatDuration(Date.now() - startTime)}`));
      printUsernameResults(target, usernameResults);
      if (strictOperational) {
        const opSummary = buildOperationalSummary(usernameResults);
        if (opSummary.quarantined.length > 0) {
          console.log(chalk.yellow(`  🧪 Quarentena SOC/IR: ${opSummary.quarantined.length} plataforma(s) inconclusiva(s)/bloqueada(s)`));
        }
      }

      // --- DORK ENGINE (DYNAMIC SCRAPING) ---
      const dorkSpinner = ora({ text: chalk.yellow(` Vasculhando motores de busca (Dorking) por "${target}"...`), spinner: 'dots12', color: 'cyan' }).start();
      const dorkResults = await searchDorks(target);
      if (dorkResults.length > 0) {
        dorkSpinner.succeed(chalk.green(` Dorking concluído — ${dorkResults.length} menções dinâmicas encontradas!`));
        console.log(chalk.cyan.bold('\n  🕸️  RESULTADOS DINÂMICOS (SEARCH ENGINES)'));
        for (const dr of dorkResults) {
          const confColor = dr.confidence === 'HIGH' ? chalk.green('HIGH') : chalk.yellow('MEDIUM');
          console.log(`  ${chalk.gray('▸')} ${chalk.white(dr.domain.padEnd(20))} [${confColor}] ${chalk.blue(dr.url)}`);
        }
      } else {
        dorkSpinner.info(chalk.gray(` Dorking concluído — Nenhuma menção dinâmica adicional encontrada.`));
      }

      finalIntel = correlateResults(target, usernameResults, emailResults || []);
      let intelStr = chalk.white(`Score de Presença: `) + (finalIntel.presenceScore > 50 ? chalk.red(finalIntel.presenceScore) : chalk.green(finalIntel.presenceScore)) + '/100\n';
      intelStr += chalk.white(`Score de Risco:    `) + (finalIntel.finalRiskScore >= 75 ? chalk.red(finalIntel.finalRiskScore) : chalk.yellow(finalIntel.finalRiskScore)) + '/100\n';
      intelStr += chalk.white(`Conf. Intel:       `) + chalk.cyan(`${finalIntel.intelligenceConfidence}/100`) + '\n';
      intelStr += chalk.white(`Nível de Risco:    `) + chalk.yellow(finalIntel.riskLevel) + '\n';
      intelStr += chalk.white(`Perfil:            `) + chalk.cyan(finalIntel.profileType) + '\n';
      if (finalIntel.metadataIntel.inferredNames.length > 0) {
        intelStr += chalk.white(`Nomes Inferidos:   `) + chalk.gray(finalIntel.metadataIntel.inferredNames.slice(0, 3).join(', ')) + '\n';
      }
      if (finalIntel.behaviorIntel.flags.length > 0) {
        intelStr += chalk.white(`Flags Intel:       `) + chalk.red(finalIntel.behaviorIntel.flags.map(f => `${f.type}(${f.severity})`).join(', ')) + '\n';
      }
      if (finalIntel.behaviorIntel.recommendations.length > 0) {
        intelStr += chalk.white(`Próx. passos:      `) + chalk.gray(finalIntel.behaviorIntel.recommendations[0]) + '\n';
      }
      if (finalIntel.evidenceTrail.length > 0) {
        intelStr += chalk.white(`Evidências:        `) + chalk.gray(finalIntel.evidenceTrail[0]) + '\n';
      }
      console.log('\n' + createDossierPanel('🧠 DOSSIÊ DE INTELIGÊNCIA', intelStr, 'magenta') + '\n');
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
  .option('--retry-blocked', 'Reexecuta plataformas inicialmente bloqueadas por WAF/anti-bot')
  .option('--retry-delay <ms>', 'Delay antes do retry de bloqueados')
  .option('--retry-attempts <n>', 'Número de tentativas progressivas para bloqueados')
  .option('--strict-operational', 'Habilita modo SOC/IR: CONFIRMED | INCONCLUSIVE | BLOCKED | ERROR')
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

// REPL Mode replaced by Wizard UI

// ═══════════════════════════════════════════
program.parse(process.argv);

if (!process.argv.slice(2).length) {
  import('./src/cli/wizard.js')
    .then(({ startWizard }) => startWizard())
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
