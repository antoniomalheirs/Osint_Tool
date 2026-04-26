/**
 * OSINT Hunter v2.0 — Email Intelligence Module
 * Busca de e-mails usando APIs gratuitas, DNS MX, e Dorks
 */

import { md5, extractDomainFromEmail } from './utils.js';
import { getNetwork } from './network.js';
import { getLogger } from './logger.js';
import { analyzeDomain } from './dnsIntel.js';

const log = getLogger('EMAIL_INTEL');

/**
 * Verifica se existe um Gravatar associado ao e-mail
 */
async function checkGravatar(email) {
  const hash = md5(email);
  const url = `https://www.gravatar.com/avatar/${hash}?d=404`;
  const profileUrl = `https://en.gravatar.com/${hash}.json`;
  const network = getNetwork();

  try {
    const res = await network.head(url);
    if (res.status === 200) {
      // Tenta puxar o JSON do perfil para extrair mais info
      let info = 'Avatar encontrado';
      try {
        const { data } = await network.getJSON(profileUrl);
        if (data && data.entry && data.entry[0]) {
          const entry = data.entry[0];
          info += ` | Nome: ${entry.displayName || entry.preferredUsername || 'N/A'}`;
          if (entry.urls && entry.urls.length > 0) {
            info += ` | Links associados: ${entry.urls.length}`;
          }
        }
      } catch { /* Ignora se não conseguir puxar o perfil completo */ }

      return {
        service: 'Gravatar',
        found: true,
        url: `https://www.gravatar.com/${hash}`,
        info,
      };
    }
    return { service: 'Gravatar', found: false, url: null, info: null };
  } catch (error) {
    log.debug('Gravatar check failed', { error: error.message });
    return { service: 'Gravatar', found: false, url: null, info: null, error: error.message };
  }
}

/**
 * Busca perfil do GitHub pelo e-mail
 */
async function checkGitHubEmail(email) {
  const url = `https://api.github.com/search/users?q=${encodeURIComponent(email)}+in:email`;
  const network = getNetwork();
  try {
    const { data, response } = await network.getJSON(url, {
      headers: { 'Accept': 'application/vnd.github.v3+json' },
    });
    
    if (response.status === 403) {
      log.warn('GitHub API rate limited');
      return { service: 'GitHub', found: null, url: null, info: 'API Rate Limited' };
    }

    if (data && data.total_count > 0) {
      const users = data.items.map(u => ({ login: u.login, profile: u.html_url }));
      return {
        service: 'GitHub',
        found: true,
        url: users[0].profile,
        info: `Contas encontradas: ${users.map(u => u.login).join(', ')}`,
        data: users,
      };
    }
    return { service: 'GitHub', found: false, url: null, info: null };
  } catch (error) {
    log.debug('GitHub check failed', { error: error.message });
    return { service: 'GitHub', found: false, url: null, info: null, error: error.message };
  }
}

/**
 * Verifica Have I Been Pwned (Apenas gera link, v3 requer auth)
 */
async function checkHIBP(email) {
  return {
    service: 'Have I Been Pwned',
    found: null,
    url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
    info: 'Verifique manualmente — Link gerado para consulta direta',
  };
}

/**
 * Verifica Holehe (Links úteis para OSINT manual)
 */
async function generateDorks(email) {
  const enc = encodeURIComponent(`"${email}"`);
  return [
    {
      service: 'Google Dork (Exata)',
      found: null,
      url: `https://www.google.com/search?q=${enc}`,
      info: 'Busca pela string exata do e-mail',
    },
    {
      service: 'Google Dork (Vazamentos)',
      found: null,
      url: `https://www.google.com/search?q=${enc}+ext:txt+OR+ext:csv+OR+ext:sql`,
      info: 'Busca e-mail em arquivos de texto, CSV ou SQL expostos',
    },
    {
      service: 'DuckDuckGo Search',
      found: null,
      url: `https://duckduckgo.com/?q=${enc}`,
      info: 'Busca anônima no DuckDuckGo',
    },
    {
      service: 'Skype Resolver (Web)',
      found: null,
      url: `https://web.skype.com/`,
      info: 'Você pode pesquisar este e-mail no Skype Web para revelar o nome real',
    }
  ];
}

/**
 * Executa todas as buscas de inteligência de e-mail e DNS
 */
export async function searchEmail(email, onResult = null) {
  log.info(`Iniciando Email Intel para: ${email}`);
  const domain = extractDomainFromEmail(email);

  // 1. Buscas baseadas em API
  const checks = [
    checkGravatar(email),
    checkGitHubEmail(email),
    checkHIBP(email),
  ];

  const results = await Promise.all(checks);

  // 2. Inteligência de Domínio
  if (domain && !['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com'].includes(domain)) {
    log.info(`Domínio customizado detectado (${domain}), iniciando análise DNS...`);
    const domainIntel = await analyzeDomain(domain);
    
    let info = `Provedor corporativo: ${domainIntel.provider}`;
    if (domainIntel.whois && domainIntel.whois.creationDate) {
      info += ` | Domínio registrado em: ${domainIntel.whois.creationDate.split('T')[0]}`;
    }

    results.push({
      service: 'Domain Intelligence',
      found: true,
      url: `https://whois.domaintools.com/${domain}`,
      info,
      data: domainIntel,
    });
  } else if (domain) {
    results.push({
      service: 'Domain Intelligence',
      found: true,
      url: null,
      info: `Provedor público: ${domain} (WHOIS/MX ignorados para provedores genéricos)`,
    });
  }

  // 3. Dorks
  const dorks = await generateDorks(email);
  const allResults = [...results, ...dorks];

  if (onResult) {
    for (const r of allResults) {
      onResult(r);
    }
  }

  log.info(`Email Intel finalizado para: ${email}. ${allResults.length} checkpoints verificados.`);
  return allResults;
}
