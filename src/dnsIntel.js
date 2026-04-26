/**
 * OSINT Hunter v2.0 — DNS & Domain Intelligence Module
 * Realiza investigações de DNS e WHOIS para domínios de e-mails
 */

import dns from 'node:dns/promises';
import { getNetwork } from './network.js';
import { getLogger } from './logger.js';
import { isDomain } from './utils.js';

const log = getLogger('DNS_INTEL');

/**
 * Consulta registros MX de um domínio
 */
export async function getMXRecords(domain) {
  if (!isDomain(domain)) return null;
  try {
    const records = await dns.resolveMx(domain);
    // Ordena por prioridade
    records.sort((a, b) => a.priority - b.priority);
    log.debug(`MX Records for ${domain}:`, records);
    return records;
  } catch (error) {
    log.debug(`Failed to get MX records for ${domain}: ${error.message}`);
    return null;
  }
}

/**
 * Analisa os registros MX para identificar o provedor de e-mail corporativo
 */
export function identifyEmailProvider(mxRecords) {
  if (!mxRecords || mxRecords.length === 0) return 'Unknown / No MX Records';

  const mxString = mxRecords.map(r => r.exchange.toLowerCase()).join(' ');

  if (mxString.includes('google.com') || mxString.includes('googlemail.com')) return 'Google Workspace (G Suite)';
  if (mxString.includes('outlook.com') || mxString.includes('protection.outlook.com')) return 'Microsoft Office 365';
  if (mxString.includes('protonmail.ch') || mxString.includes('protonmail.com')) return 'ProtonMail';
  if (mxString.includes('zoho.com')) return 'Zoho Mail';
  if (mxString.includes('yandex.net') || mxString.includes('yandex.ru')) return 'Yandex Connect';
  if (mxString.includes('fastmail.com')) return 'Fastmail';
  if (mxString.includes('apple.com')) return 'iCloud Mail';

  // Se não for nenhum dos conhecidos corporativos, retorna o MX primário
  return `Custom / ${mxRecords[0].exchange}`;
}

/**
 * Busca dados de WHOIS via API pública (NetworkCalc)
 */
export async function getWhoisInfo(domain) {
  if (!isDomain(domain)) return null;
  const network = getNetwork();
  try {
    const { data } = await network.getJSON(`https://networkcalc.com/api/dns/whois/${domain}`);
    if (data && data.status === 'OK' && data.whois) {
      log.debug(`WHOIS info for ${domain} retrieved`);
      return {
        registrar: data.whois.registrar || 'Unknown',
        creationDate: data.whois.creation_date || 'Unknown',
        expirationDate: data.whois.expiration_date || 'Unknown',
        nameservers: data.whois.name_servers || [],
        raw: data.whois,
      };
    }
    return null;
  } catch (error) {
    log.debug(`Failed to get WHOIS for ${domain}: ${error.message}`);
    return null;
  }
}

/**
 * Executa análise de domínio completa
 */
export async function analyzeDomain(domain) {
  if (!isDomain(domain)) {
    return { error: 'Domínio inválido' };
  }

  log.info(`Analisando domínio: ${domain}`);
  
  const [mxRecords, whois] = await Promise.all([
    getMXRecords(domain),
    getWhoisInfo(domain)
  ]);

  const provider = identifyEmailProvider(mxRecords);

  return {
    domain,
    provider,
    mxRecords,
    whois,
  };
}
