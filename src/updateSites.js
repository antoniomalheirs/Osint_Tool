import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import chalk from 'chalk';
import { getNetwork } from './network.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sitesPath = path.join(__dirname, '..', 'data', 'sites.json');

const WMN_URL = 'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json';

async function updateSites() {
  console.log(chalk.cyan('📥 Baixando base de dados do WhatsMyName...'));
  
  const network = getNetwork();
  let data;
  try {
    const res = await network.getJSON(WMN_URL);
    data = res.data;
  } catch (err) {
    console.error(chalk.red('Falha ao baixar dados do WhatsMyName: ' + err.message));
    process.exit(1);
  }

  if (!data || !data.sites || !Array.isArray(data.sites)) {
    console.error(chalk.red('Formato inválido recebido do WhatsMyName.'));
    process.exit(1);
  }

  console.log(chalk.green(`✓ Recebidos ${data.sites.length} sites do WhatsMyName.`));

  let currentSites = [];
  if (fs.existsSync(sitesPath)) {
    try {
      currentSites = JSON.parse(fs.readFileSync(sitesPath, 'utf8'));
      console.log(chalk.yellow(`Lendo banco de dados atual (${currentSites.length} sites).`));
    } catch (e) {
      console.error(chalk.red('Erro ao ler data/sites.json: ' + e.message));
    }
  }

  const existingNames = new Set(currentSites.map(s => s.name.toLowerCase()));
  let added = 0;

  for (const site of data.sites) {
    const nameLower = site.name.toLowerCase();
    
    // Pula sites que já temos (para preservar configurações customizadas super-validadas do OSINT Hunter)
    if (existingNames.has(nameLower)) {
      continue;
    }

    // Traduz o schema do WhatsMyName para OSINT Hunter
    const newSite = {
      name: site.name,
      category: site.cat || 'Outros',
      url: site.uri_check.replace('{account}', '{username}'),
      isNSFW: site.cat === 'porno' // WhatsMyName usa 'porno' ou tags similares em versões antigas
    };

    if (site.m_string) {
      newSite.method = 'message';
      newSite.errorMsg = site.m_string;
    } else if (site.e_string) {
      newSite.method = 'message';
      newSite.expectedMsg = site.e_string;
    } else {
      newSite.method = 'status_code';
      newSite.expectedStatus = site.e_code || 200;
      if (site.m_code) {
        newSite.errorCode = site.m_code;
      }
    }

    currentSites.push(newSite);
    existingNames.add(nameLower);
    added++;
  }

  // Ordena alfabeticamente para organização
  currentSites.sort((a, b) => a.name.localeCompare(b.name));

  fs.writeFileSync(sitesPath, JSON.stringify(currentSites, null, 2), 'utf8');
  console.log(chalk.green.bold(`\n🎉 Atualização concluída! ${added} novos sites adicionados.`));
  console.log(chalk.cyan(`O OSINT Hunter agora possui um total de ${currentSites.length} plataformas no arsenal.`));
}

updateSites();
