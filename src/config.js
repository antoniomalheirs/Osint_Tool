/**
 * OSINT Hunter v2.0 — Configuration Manager
 * Carrega e processa as configurações YAML
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = path.join(__dirname, '..', 'config', 'default.yml');

let _config = null;

export function loadConfig() {
  if (_config) return _config;

  try {
    const file = fs.readFileSync(CONFIG_PATH, 'utf8');
    _config = YAML.parse(file);
    return _config;
  } catch (error) {
    console.warn(`[WARN] Não foi possível carregar config/default.yml. Usando padrões internos. Erro: ${error.message}`);
    // Padrões hardcoded caso o arquivo falhe/seja apagado
    _config = {
      network: { timeout: 15000, maxRetries: 2, concurrency: 20, domainDelay: 200 },
      search: { includeNSFW: false, exportFormat: 'none' },
      database: { enabled: true, filename: 'osint_history.db' },
      logging: { level: 'INFO', toFile: true }
    };
    return _config;
  }
}

export function getConfig() {
  return _config || loadConfig();
}
