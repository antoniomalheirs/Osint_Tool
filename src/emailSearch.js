/**
 * OSINT Hunter v2.0 — Email Intelligence Module
 * Busca de e-mails usando APIs gratuitas, DNS MX, e Dorks
 */

import { md5, extractDomainFromEmail } from './utils.js';
import { getNetwork } from './network.js';
import { getLogger } from './logger.js';
import { analyzeDomain } from './dnsIntel.js';
import { validateEmailSmtp } from './smtpValidation.js';
import { executeAdvancedDorks } from './dorkEngine.js';

const log = getLogger('EMAIL_INTEL');

export const EMAIL_STATUS = {
  CONFIRMED: 'CONFIRMED',
  INCONCLUSIVE: 'INCONCLUSIVE',
  LINK_ONLY: 'LINK_ONLY',
  ERROR: 'ERROR',
};

function normalizeEmailResult(result) {
  const normalized = { ...result };
  if (normalized.error) normalized.status = EMAIL_STATUS.ERROR;
  else if (normalized.found === true) normalized.status = EMAIL_STATUS.CONFIRMED;
  else if (normalized.found === false) normalized.status = EMAIL_STATUS.INCONCLUSIVE;
  else normalized.status = EMAIL_STATUS.LINK_ONLY;

  if (!normalized.confidence) {
    normalized.confidence = normalized.status === EMAIL_STATUS.CONFIRMED
      ? 'HIGH'
      : normalized.status === EMAIL_STATUS.ERROR
        ? 'LOW'
        : 'MEDIUM';
  }
  return normalized;
}

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
      return normalizeEmailResult({ service: 'GitHub', found: null, url: null, info: 'API Rate Limited', reason: 'RATE_LIMIT' });
    }

    if (data && data.total_count > 0) {
      const users = await Promise.all(data.items.slice(0, 5).map(async (u) => {
        let details = null;
        try {
          const { data: profile } = await network.getJSON(u.url, {
            headers: { 'Accept': 'application/vnd.github.v3+json' },
          });
          details = {
            name: profile?.name || null,
            company: profile?.company || null,
            location: profile?.location || null,
          };
        } catch {
          details = null;
        }
        return {
          login: u.login,
          profile: u.html_url,
          ...details,
        };
      }));
      const enriched = users
        .map((u) => {
          const extras = [u.name, u.company].filter(Boolean).join(' | ');
          return extras ? `${u.login} (${extras})` : u.login;
        })
        .join(', ');
      return {
        service: 'GitHub',
        found: true,
        url: users[0].profile,
        info: `Contas encontradas: ${enriched}`,
        data: users,
        reason: 'MATCH_FOUND',
      };
    }
    return normalizeEmailResult({ service: 'GitHub', found: false, url: null, info: null, reason: 'NO_MATCH' });
  } catch (error) {
    log.debug('GitHub check failed', { error: error.message });
    return normalizeEmailResult({ service: 'GitHub', found: false, url: null, info: null, error: error.message, reason: 'REQUEST_ERROR' });
  }
}

/**
 * Verifica Have I Been Pwned (Apenas gera link, v3 requer auth)
 */
async function checkHIBP(email) {
  return normalizeEmailResult({
    service: 'Have I Been Pwned',
    found: null,
    url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
    info: 'Verifique manualmente — Link gerado para consulta direta',
    reason: 'MANUAL_LINK',
  });
}

/**
 * Verifica reputação do e-mail no EmailRep.io
 */
async function checkEmailRep(email) {
  const url = `https://emailrep.io/${encodeURIComponent(email)}`;
  const network = getNetwork();
  try {
    const { data, response } = await network.getJSON(url);
    if (response.status === 429) {
      log.warn('EmailRep.io rate limited');
      return normalizeEmailResult({ service: 'EmailRep.io', found: null, url: null, info: 'API Rate Limited', reason: 'RATE_LIMIT' });
    }
    
    if (data && data.details) {
      let info = `Reputação: ${data.reputation}`;
      if (data.details.suspicious) info += ' | SUSPEITO';
      if (data.details.credentials_leaked) info += ' | VAZAMENTO CREDENCIAIS';
      if (data.details.data_breach) info += ' | ENVOLVIDO EM DATA BREACH';
      if (data.details.disposable) info += ' | DESCARTÁVEL';

      return normalizeEmailResult({
        service: 'EmailRep.io',
        found: true,
        url: null,
        info,
        data,
        reason: 'REPUTATION_INTEL'
      });
    }
    return normalizeEmailResult({ service: 'EmailRep.io', found: null, url: null, info: 'Sem dados suficientes', reason: 'NO_DATA' });
  } catch (error) {
    log.debug('EmailRep.io check failed', { error: error.message });
    return normalizeEmailResult({ service: 'EmailRep.io', found: false, url: null, info: null, error: error.message, reason: 'REQUEST_ERROR' });
  }
}

/**
 * Verifica se é descartável via Kickbox Open API
 */
async function checkKickbox(email) {
  const url = `https://open.kickbox.com/v1/disposable/${encodeURIComponent(email)}`;
  const network = getNetwork();
  try {
    const { data } = await network.getJSON(url);
    if (data && typeof data.is_disposable === 'boolean') {
      return normalizeEmailResult({
        service: 'Kickbox Disposable Check',
        found: data.is_disposable,
        url: null,
        info: data.is_disposable ? 'E-mail descartável confirmado' : 'Não é e-mail descartável conhecido',
        reason: 'DISPOSABLE_CHECK'
      });
    }
    return normalizeEmailResult({ service: 'Kickbox Disposable Check', found: null, url: null, info: null, reason: 'NO_DATA' });
  } catch (error) {
    log.debug('Kickbox check failed', { error: error.message });
    return normalizeEmailResult({ service: 'Kickbox Disposable Check', found: false, url: null, info: null, error: error.message, reason: 'REQUEST_ERROR' });
  }
}

/**
 * Verifica Holehe (Links úteis para OSINT manual)
 */
async function generateDorks(email) {
  const scraped = await executeAdvancedDorks(email, 'email');
  if (!scraped.length) {
    return [normalizeEmailResult({
      service: 'Web Dorking (DuckDuckGo)',
      found: null,
      url: `https://duckduckgo.com/?q=${encodeURIComponent(`"${email}"`)}`,
      info: 'Nenhum resultado coletado automaticamente (possível bloqueio/rate-limit).',
      reason: 'NO_SCRAPED_RESULTS',
    })];
  }

  return scraped.slice(0, 20).map((result) => normalizeEmailResult({
    service: `Web Dorking (${result.dorkType})`,
    found: true,
    url: result.url,
    info: `Domínio: ${result.domain} | Confiança: ${result.confidence}`,
    data: result,
    confidence: result.confidence,
    reason: 'DORK_RESULT',
  }));
}

function derivePivotTermsFromEmail(email, intelResults) {
  const pivots = [];
  const seen = new Set();
  const addPivot = (term, source, type = 'username') => {
    const clean = String(term || '').trim();
    if (clean.length < 3) return;
    const key = `${type}:${clean.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    pivots.push({ term: clean, source, type });
  };

  // 1) Deriva username a partir do local-part do e-mail
  const localPart = String(email).split('@')[0] || '';
  addPivot(localPart, 'email_local_part', 'username');
  localPart
    .split(/[._\-+]/g)
    .filter(Boolean)
    .forEach(token => addPivot(token, 'email_token', 'username'));

  // 2) Deriva termos de perfil GitHub enriquecido
  const github = intelResults.find(r => r.service === 'GitHub' && Array.isArray(r.data));
  if (github) {
    for (const user of github.data.slice(0, 5)) {
      addPivot(user.login, 'github_login', 'username');
      if (user.name) addPivot(user.name, 'github_name', 'name');
      if (user.company) addPivot(user.company, 'github_company', 'company');
    }
  }

  // 3) Deriva nome do Gravatar se disponível
  const gravatar = intelResults.find(r => r.service === 'Gravatar' && r.found && r.info);
  if (gravatar && typeof gravatar.info === 'string') {
    const m = gravatar.info.match(/Nome:\s*([^|]+)/i);
    if (m && m[1]) {
      addPivot(m[1], 'gravatar_name', 'name');
    }
  }

  return pivots.slice(0, 4);
}

async function runAutomaticPivoting(pivotTerms) {
  if (!pivotTerms.length) return [];
  const aggregated = [];

  for (const pivot of pivotTerms) {
    const pivotResults = await executeAdvancedDorks(pivot.term, pivot.type);
    if (!pivotResults.length) continue;
    aggregated.push(...pivotResults.slice(0, 8).map(result => normalizeEmailResult({
      service: `Auto Pivot (${pivot.type.toUpperCase()})`,
      found: true,
      url: result.url,
      info: `Pivot: "${pivot.term}" (${pivot.source}) | Domínio: ${result.domain} | Confiança: ${result.confidence}`,
      data: { ...result, pivotSource: pivot.source, pivotTerm: pivot.term },
      confidence: result.confidence,
      reason: 'AUTO_PIVOT_DORK_RESULT',
    })));
  }

  return aggregated;
}

async function withRetry(fn, retries = 2, delayMs = 800) {
  let lastErr = null;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        await new Promise(resolve => setTimeout(resolve, delayMs * attempt));
      }
    }
  }
  throw lastErr;
}

/**
 * Executa todas as buscas de inteligência de e-mail e DNS
 */
export async function searchEmail(email, onResult = null) {
  log.info(`Iniciando Email Intel para: ${email}`);
  const domain = extractDomainFromEmail(email);

  // 1. Buscas baseadas em API
  const checks = [
    () => checkGravatar(email),
    () => withRetry(() => checkGitHubEmail(email), 2, 1000),
    () => checkHIBP(email),
    () => checkEmailRep(email),
    () => checkKickbox(email),
  ];

  const rawResults = await Promise.all(checks.map(fn => fn()));
  const results = rawResults.map(normalizeEmailResult);

  // 1.5 Validação SMTP Direta
  const smtpResult = await validateEmailSmtp(email);
  results.push(normalizeEmailResult(smtpResult));

  // 2. Inteligência de Domínio
  if (domain && !['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com'].includes(domain)) {
    log.info(`Domínio customizado detectado (${domain}), iniciando análise DNS...`);
    const domainIntel = await analyzeDomain(domain);
    
    let info = `Provedor corporativo: ${domainIntel.provider}`;
    if (domainIntel.whois && domainIntel.whois.creationDate) {
      info += ` | Domínio registrado em: ${domainIntel.whois.creationDate.split('T')[0]}`;
    }

    results.push(normalizeEmailResult({
      service: 'Domain Intelligence',
      found: true,
      url: `https://whois.domaintools.com/${domain}`,
      info,
      data: domainIntel,
      reason: 'DOMAIN_INTEL',
    }));
  } else if (domain) {
    results.push(normalizeEmailResult({
      service: 'Domain Intelligence',
      found: true,
      url: null,
      info: `Provedor público: ${domain} (WHOIS/MX ignorados para provedores genéricos)`,
      reason: 'PUBLIC_PROVIDER',
    }));
  }

  // 3. Dorks diretas no e-mail
  const dorks = await generateDorks(email);

  // 4. Pivoting automático: termos derivados de username/nome/empresa
  const pivotTerms = derivePivotTermsFromEmail(email, results);
  const autoPivotResults = await runAutomaticPivoting(pivotTerms);
  if (pivotTerms.length > 0) {
    results.push(normalizeEmailResult({
      service: 'Automatic Pivoting',
      found: autoPivotResults.length > 0,
      url: null,
      info: autoPivotResults.length > 0
        ? `Pivoting automático executado com ${pivotTerms.length} termo(s).`
        : `Pivoting automático sugerido com ${pivotTerms.length} termo(s), mas sem novos hits.`,
      data: pivotTerms,
      reason: autoPivotResults.length > 0 ? 'AUTO_PIVOT_EXECUTED' : 'AUTO_PIVOT_NO_HITS',
      confidence: autoPivotResults.length > 0 ? 'HIGH' : 'MEDIUM',
    }));
  }

  const allResults = [...results, ...dorks, ...autoPivotResults];

  if (onResult) {
    for (const r of allResults) {
      onResult(r);
    }
  }

  log.info(`Email Intel finalizado para: ${email}. ${allResults.length} checkpoints verificados.`);
  return allResults;
}
