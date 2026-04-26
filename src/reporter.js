/**
 * OSINT Hunter — Reporter Module
 * Formatação de resultados e exportação para arquivos
 */

import chalk from 'chalk';
import Table from 'cli-table3';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

// Garante que o diretório de reports existe
if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

/**
 * Exibe o banner ASCII da ferramenta
 */
export function printBanner() {
  const banner = chalk.cyan.bold(`
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
  ║`) + chalk.yellow.bold(`       🔍  H U N T E R  —  OSINT Tool v2.0`) + chalk.cyan.bold(`            ║
  ║`) + chalk.gray(`       Professional Cyber Intelligence Gatherer`) + chalk.cyan.bold(`      ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
  `);
  console.log(banner);
}

/**
 * Exibe a tabela de resultados de busca por username
 */
export function printUsernameResults(username, results) {
  const found = results.filter(r => r.operationalStatus === 'CONFIRMED');
  const blocked = results.filter(r => r.operationalStatus === 'BLOCKED');
  const inconclusive = results.filter(r => r.operationalStatus === 'INCONCLUSIVE');
  const errors = results.filter(r => r.operationalStatus === 'ERROR');

  console.log('\n' + chalk.cyan.bold('━'.repeat(60)));
  console.log(chalk.white.bold(`  📊 Resultados para: `) + chalk.yellow.bold(username));
  console.log(chalk.cyan.bold('━'.repeat(60)));

  // Tabela de perfis encontrados
  if (found.length > 0) {
    console.log('\n' + chalk.green.bold(`  ✅ PERFIS ENCONTRADOS (${found.length})`));

    const table = new Table({
      head: [
        chalk.white.bold('Plataforma'),
        chalk.white.bold('Categoria'),
        chalk.white.bold('URL'),
        chalk.white.bold('Tempo'),
      ],
      colWidths: [22, 20, 50, 10],
      style: { head: [], border: ['cyan'] },
      chars: {
        'top': '─', 'top-mid': '┬', 'top-left': '┌', 'top-right': '┐',
        'bottom': '─', 'bottom-mid': '┴', 'bottom-left': '└', 'bottom-right': '┘',
        'left': '│', 'left-mid': '├', 'mid': '─', 'mid-mid': '┼',
        'right': '│', 'right-mid': '┤', 'middle': '│',
      },
    });

    for (const r of found) {
      table.push([
        chalk.green(r.site),
        chalk.gray(r.category),
        chalk.blue.underline(r.url),
        chalk.gray(`${r.responseTime}ms`),
      ]);
    }

    console.log(table.toString());
  }

  // Resumo
  console.log('\n' + chalk.cyan.bold('━'.repeat(60)));
  console.log(chalk.white.bold('  📈 RESUMO'));
  console.log(chalk.green(`     ✅ Encontrados:   ${found.length}`));
  console.log(chalk.gray(`     ❓ Inconclusivos: ${inconclusive.length}`));
  console.log(chalk.yellow(`     🛡️  Bloqueados:    ${blocked.length}`));
  console.log(chalk.red(`     ⚠️  Erros/Timeout: ${errors.length}`));
  console.log(chalk.gray(`     📡 Total checado: ${results.length} plataformas`));
  console.log(chalk.cyan.bold('━'.repeat(60)) + '\n');
}

/**
 * Exibe resultados de busca por e-mail
 */
export function printEmailResults(email, results) {
  console.log('\n' + chalk.magenta.bold('━'.repeat(60)));
  console.log(chalk.white.bold(`  📧 Resultados para E-mail: `) + chalk.yellow.bold(email));
  console.log(chalk.magenta.bold('━'.repeat(60)));

  const table = new Table({
    head: [
      chalk.white.bold('Serviço'),
      chalk.white.bold('Status'),
      chalk.white.bold('Confiança'),
      chalk.white.bold('Info'),
    ],
    colWidths: [22, 14, 14, 44],
    style: { head: [], border: ['magenta'] },
    wordWrap: true,
  });

  const summary = {
    CONFIRMED: 0,
    INCONCLUSIVE: 0,
    LINK_ONLY: 0,
    ERROR: 0,
  };

  for (const r of results) {
    const status = r.status === 'CONFIRMED'
      ? chalk.green.bold('CONFIRMED')
      : r.status === 'INCONCLUSIVE'
        ? chalk.gray('INCONCLUSIVE')
        : r.status === 'ERROR'
          ? chalk.red('ERROR')
          : chalk.yellow('LINK_ONLY');
    summary[r.status || 'INCONCLUSIVE'] = (summary[r.status || 'INCONCLUSIVE'] || 0) + 1;

    table.push([
      chalk.white(r.service),
      status,
      chalk.cyan(r.confidence || 'MEDIUM'),
      r.info ? chalk.gray(r.info) : (r.url ? chalk.blue.underline(r.url) : chalk.gray('—')),
    ]);
  }

  console.log(table.toString());
  console.log(chalk.gray(`  Resumo Email Intel → CONFIRMED: ${summary.CONFIRMED} | INCONCLUSIVE: ${summary.INCONCLUSIVE} | LINK_ONLY: ${summary.LINK_ONLY} | ERROR: ${summary.ERROR}`));
  console.log(chalk.magenta.bold('━'.repeat(60)) + '\n');
}

/**
 * Exporta resultados para JSON
 */
export function exportJSON(target, usernameResults, emailResults) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `osint_${target}_${timestamp}.json`;
  const filepath = path.join(REPORTS_DIR, filename);

  const report = {
    tool: 'OSINT Hunter v2.0',
    target,
    timestamp: new Date().toISOString(),
    username_search: usernameResults ? {
      total: usernameResults.length,
      found: usernameResults.filter(r => r.found).length,
      results: usernameResults,
    } : null,
    email_search: emailResults || null,
  };

  fs.writeFileSync(filepath, JSON.stringify(report, null, 2), 'utf-8');
  console.log(chalk.green.bold(`  💾 Relatório JSON salvo em: `) + chalk.underline(filepath));
  return filepath;
}

/**
 * Exporta resultados para CSV
 */
export function exportCSV(target, usernameResults) {
  if (!usernameResults) return;

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `osint_${target}_${timestamp}.csv`;
  const filepath = path.join(REPORTS_DIR, filename);

  const header = 'Plataforma,Categoria,URL,Encontrado,Status Code,Tempo (ms),Erro\n';
  const rows = usernameResults.map(r =>
    `"${r.site}","${r.category}","${r.url}",${r.found},${r.statusCode || ''},${r.responseTime},"${r.error || ''}"`
  ).join('\n');

  fs.writeFileSync(filepath, header + rows, 'utf-8');
  console.log(chalk.green.bold(`  📄 Relatório CSV salvo em: `) + chalk.underline(filepath));
  return filepath;
}

/**
 * Exporta resultados para TXT
 */
export function exportTXT(target, usernameResults, emailResults) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `osint_${target}_${timestamp}.txt`;
  const filepath = path.join(REPORTS_DIR, filename);

  let content = `═══════════════════════════════════════\n`;
  content += ` OSINT Hunter — Relatório\n`;
  content += ` Alvo: ${target}\n`;
  content += ` Data: ${new Date().toLocaleString('pt-BR')}\n`;
  content += `═══════════════════════════════════════\n\n`;

  if (usernameResults) {
    const found = usernameResults.filter(r => r.found && !r.error);
    content += `[USERNAME SEARCH] — ${found.length} perfis encontrados em ${usernameResults.length} plataformas\n\n`;
    for (const r of found) {
      content += `  ✅ ${r.site.padEnd(25)} ${r.url}\n`;
    }
    content += '\n';
  }

  if (emailResults) {
    content += `[EMAIL SEARCH]\n\n`;
    for (const r of emailResults) {
      const status = r.found === true ? '✅' : r.found === false ? '❌' : '🔗';
      content += `  ${status} ${r.service.padEnd(25)} ${r.url || ''}\n`;
      if (r.info) content += `     └─ ${r.info}\n`;
    }
  }

  fs.writeFileSync(filepath, content, 'utf-8');
  console.log(chalk.green.bold(`  📝 Relatório TXT salvo em: `) + chalk.underline(filepath));
  return filepath;
}

/**
 * Exporta resultados para um Relatório HTML Interativo
 */
export function exportHTML(target, usernameResults, emailResults, correlatorIntel) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `osint_${target}_${timestamp}.html`;
  const filepath = path.join(REPORTS_DIR, filename);

  const foundUsernames = usernameResults ? usernameResults.filter(r => r.found && !r.error && !r.skipped) : [];
  
  const catCount = {};
  for (const r of foundUsernames) {
    catCount[r.category] = (catCount[r.category] || 0) + 1;
  }
  const chartLabels = Object.keys(catCount);
  const chartData = Object.values(catCount);

  let correlatorSection = '';
  if (correlatorIntel) {
    const names = correlatorIntel.metadataIntel.inferredNames.length > 0 
      ? `<p class="text-sm text-gray-300 mt-2">Nomes: ${correlatorIntel.metadataIntel.inferredNames.join(', ')}</p>` 
      : '';
    const behaviorFlags = correlatorIntel.behaviorIntel?.flags || [];
    const behaviorRecommendations = correlatorIntel.behaviorIntel?.recommendations || [];
    const flagsHtml = behaviorFlags.length > 0
      ? `<div class="mt-4">
          <p class="text-gray-400 text-sm mb-2">Flags de comportamento</p>
          <div class="flex flex-wrap gap-2">
            ${behaviorFlags.map(flag => `<span class="px-2 py-1 rounded-md text-xs ${flag.severity === 'HIGH' ? 'bg-red-900 text-red-200' : 'bg-yellow-900 text-yellow-200'}">${flag.type} · ${flag.severity}</span>`).join('')}
          </div>
        </div>`
      : '<p class="text-sm text-green-400 mt-4">Nenhuma flag comportamental crítica detectada.</p>';

    const recHtml = behaviorRecommendations.length > 0
      ? `<ul class="mt-3 space-y-2 text-sm text-gray-300">${behaviorRecommendations.map(r => `<li>• ${r}</li>`).join('')}</ul>`
      : '<p class="text-sm text-gray-400 mt-3">Sem recomendações adicionais.</p>';
      
    correlatorSection = `
    <section class="glass rounded-xl p-6">
      <h2 class="text-xl font-semibold mb-4 text-magenta-400">🧠 Inteligência & Risco</h2>
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-slate-800 p-4 rounded-lg text-center border ${correlatorIntel.presenceScore > 50 ? 'border-red-500' : 'border-green-500'}">
          <p class="text-gray-400 text-sm">Presence Score</p>
          <p class="text-4xl font-bold ${correlatorIntel.presenceScore > 50 ? 'text-red-400' : 'text-green-400'}">${correlatorIntel.presenceScore}</p>
        </div>
        <div class="bg-slate-800 p-4 rounded-lg text-center border ${correlatorIntel.finalRiskScore >= 75 ? 'border-red-500' : 'border-slate-600'}">
          <p class="text-gray-400 text-sm">Risk Score (Final)</p>
          <p class="text-3xl font-bold ${correlatorIntel.finalRiskScore >= 75 ? 'text-red-400' : 'text-yellow-300'} mt-2">${correlatorIntel.finalRiskScore || 0}</p>
        </div>
        <div class="bg-slate-800 p-4 rounded-lg text-center border ${correlatorIntel.riskLevel === 'CRITICAL' ? 'border-red-500' : 'border-slate-600'}">
          <p class="text-gray-400 text-sm">Risk Level</p>
          <p class="text-2xl font-bold text-yellow-400 mt-2">${correlatorIntel.riskLevel}</p>
        </div>
        <div class="bg-slate-800 p-4 rounded-lg text-center md:col-span-1 border border-slate-600">
          <p class="text-gray-400 text-sm">Perfil Detectado</p>
          <p class="text-xl font-bold text-cyan-400 mt-2">${correlatorIntel.profileType}</p>
          ${names}
        </div>
      </div>
      <div class="mt-4">
        <p class="text-gray-400 text-sm">Confiança Analítica</p>
        <div class="w-full bg-slate-800 rounded-full h-3 mt-2">
          <div class="h-3 rounded-full ${correlatorIntel.intelligenceConfidence >= 70 ? 'bg-cyan-400' : 'bg-yellow-400'}" style="width:${correlatorIntel.intelligenceConfidence || 0}%"></div>
        </div>
        <p class="text-xs text-gray-400 mt-1">${correlatorIntel.intelligenceConfidence || 0}/100</p>
      </div>
      ${flagsHtml}
      <div class="mt-4 border-t border-slate-700 pt-4">
        <p class="text-gray-400 text-sm">Próximos passos sugeridos</p>
        ${recHtml}
      </div>
      <div class="mt-4 border-t border-slate-700 pt-4">
        <p class="text-gray-400 text-sm">Trilha de evidências</p>
        <ul class="mt-3 space-y-2 text-sm text-gray-300">
          ${(correlatorIntel.evidenceTrail || []).slice(0, 6).map(item => `<li>• ${item}</li>`).join('') || '<li>• Sem evidências textuais adicionais</li>'}
        </ul>
      </div>
    </section>`;
  }

  let tableRows = '';
  for (const r of foundUsernames) {
    const confClass = r.confidence === 'HIGH' ? 'bg-green-900 text-green-300' : 'bg-yellow-900 text-yellow-300';
    tableRows += `
    <tr class="border-b border-slate-800 hover:bg-slate-800/50">
      <td class="p-3 font-semibold text-white">${r.site}</td>
      <td class="p-3 text-gray-400">${r.category}</td>
      <td class="p-3">
        <span class="px-2 py-1 rounded text-xs ${confClass}">${r.confidence}</span>
      </td>
      <td class="p-3"><a href="${r.url}" target="_blank" class="text-cyan-400 hover:underline">Acessar ↗</a></td>
    </tr>`;
  }

  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OSINT Hunter Report - ${target}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { background-color: #0f172a; color: #f8fafc; font-family: 'Inter', sans-serif; }
    .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }
  </style>
</head>
<body class="min-h-screen p-8">
  <div class="max-w-6xl mx-auto space-y-6">
    <header class="glass rounded-xl p-6 flex justify-between items-center">
      <div>
        <h1 class="text-3xl font-bold text-cyan-400 flex items-center gap-3">
          🔍 OSINT Hunter <span class="text-xs bg-cyan-900 text-cyan-300 px-2 py-1 rounded">v2.0</span>
        </h1>
        <p class="text-gray-400 mt-2">Relatório de Inteligência Digital</p>
      </div>
      <div class="text-right">
        <p class="text-sm text-gray-500">Alvo Investigado</p>
        <p class="text-2xl font-mono text-yellow-400">${target}</p>
        <p class="text-xs text-gray-500 mt-1">${new Date().toLocaleString('pt-BR')}</p>
      </div>
    </header>

    ${correlatorSection}

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div class="glass rounded-xl p-6 col-span-1 flex flex-col items-center justify-center">
        <h2 class="text-lg font-semibold mb-4 w-full">Distribuição por Categoria</h2>
        <div class="w-full max-w-[250px]">
          <canvas id="categoryChart"></canvas>
        </div>
      </div>

      <div class="glass rounded-xl p-6 col-span-1 lg:col-span-2">
        <h2 class="text-lg font-semibold mb-4 flex justify-between">
          <span>Plataformas Encontradas</span>
          <span class="bg-green-900 text-green-300 text-sm px-3 py-1 rounded-full">${foundUsernames.length} Perfis</span>
        </h2>
        <div class="overflow-auto max-h-[400px]">
          <table class="w-full text-left text-sm">
            <thead class="sticky top-0 bg-slate-800 text-gray-400">
              <tr>
                <th class="p-3 rounded-tl">Plataforma</th>
                <th class="p-3">Categoria</th>
                <th class="p-3">Confiança</th>
                <th class="p-3 rounded-tr">Link</th>
              </tr>
            </thead>
            <tbody>
              ${tableRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
    const ctx = document.getElementById('categoryChart');
    if (ctx) {
      new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ${JSON.stringify(chartLabels)},
          datasets: [{
            data: ${JSON.stringify(chartData)},
            backgroundColor: ['#38bdf8', '#818cf8', '#c084fc', '#f472b6', '#fb7185', '#fbbf24', '#a3e635', '#34d399', '#2dd4bf'],
            borderWidth: 0
          }]
        },
        options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#cbd5e1' } } } }
      });
    }
  </script>
</body>
</html>`;

  fs.writeFileSync(filepath, html, 'utf-8');
  console.log(chalk.green.bold(`  🌐 Relatório HTML interativo salvo em: `) + chalk.underline(filepath));
  return filepath;
}
