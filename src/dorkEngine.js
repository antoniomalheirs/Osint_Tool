/**
 * OSINT Hunter v3.0 — Dynamic Dork Engine (Search Engine Scraping)
 * Vasculha a internet livre (via DuckDuckGo) por menções a usernames, e-mails e termos livres.
 */

import { getNetwork } from './network.js';
import { getLogger } from './logger.js';

const log = getLogger('DORK_ENGINE');

const DOMAIN_RELEVANCE = {
  'github.com': 3,
  'pastebin.com': 3,
  'ghostbin.co': 3,
  'gitlab.com': 2,
  'bitbucket.org': 2,
  'archive.org': 2,
  'docs.google.com': 2,
};

function unwrapDuckDuckGoLink(rawHref) {
  if (!rawHref) return null;
  if (rawHref.startsWith('//duckduckgo.com/l/?')) {
    try {
      const wrapped = new URL(`https:${rawHref}`);
      const uddg = wrapped.searchParams.get('uddg');
      return uddg ? decodeURIComponent(uddg) : null;
    } catch {
      return null;
    }
  }
  if (rawHref.startsWith('/l/?')) {
    try {
      const wrapped = new URL(`https://duckduckgo.com${rawHref}`);
      const uddg = wrapped.searchParams.get('uddg');
      return uddg ? decodeURIComponent(uddg) : null;
    } catch {
      return null;
    }
  }
  if (rawHref.startsWith('http://') || rawHref.startsWith('https://')) {
    return rawHref;
  }
  return null;
}

function sanitizeLink(url) {
  try {
    const parsed = new URL(url);
    ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'ref', 'ref_src'].forEach(p => parsed.searchParams.delete(p));
    return parsed.toString();
  } catch {
    return null;
  }
}

function classifyRelevance(domain, term, url) {
  const lowerDomain = (domain || '').toLowerCase();
  const lowerTerm = (term || '').toLowerCase();
  const lowerUrl = (url || '').toLowerCase();
  const score = DOMAIN_RELEVANCE[lowerDomain] || 1;
  const hasDirectTerm = lowerTerm && lowerUrl.includes(lowerTerm);

  if (score >= 3 || hasDirectTerm) return 'HIGH';
  if (score === 2) return 'MEDIUM';
  return 'LOW';
}

async function executeDuckDuckGoQuery(query, term, dorkType) {
  const network = getNetwork();
  const encodedQuery = encodeURIComponent(query);
  const url = `https://html.duckduckgo.com/html/?q=${encodedQuery}`;

  try {
    const response = await network.get(url, {
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Referer': 'https://duckduckgo.com/',
        'Upgrade-Insecure-Requests': '1',
      }
    });

    if (response.status !== 200) {
      log.warn(`DuckDuckGo bloqueou a requisição (Rate Limit / Captcha). Status: ${response.status}`);
      return [];
    }

    const html = await response.text();

    const urlRegex = /<a[^>]+class="(?:result__a|result__url)"[^>]+href="([^"]+)"/ig;
    let match;
    const links = [];

    while ((match = urlRegex.exec(html)) !== null) {
      const unwrapped = unwrapDuckDuckGoLink(match[1]);
      if (!unwrapped) continue;
      const clean = sanitizeLink(unwrapped);
      if (!clean) continue;
      links.push(clean);
    }

    const uniqueLinks = [...new Set(links)];
    return uniqueLinks.map((link) => {
      let domain = 'unknown';
      try {
        domain = new URL(link).hostname.replace('www.', '');
      } catch { /* ignore */ }

      return {
        domain,
        url: link,
        source: 'DuckDuckGo',
        query,
        dorkType,
        confidence: classifyRelevance(domain, term, link),
      };
    });

  } catch (error) {
    log.error(`Falha no Dork Engine: ${error.message}`);
    return [];
  }
}

export async function executeAdvancedDorks(term, type = 'username') {
  if (!term || typeof term !== 'string') return [];
  const safeTerm = term.trim();
  if (!safeTerm) return [];

  log.info(`Executando dorks avançadas para termo "${safeTerm}" (tipo: ${type})`);

  const wrapped = `"${safeTerm}"`;
  const dorks = [
    { name: 'EXACT', query: wrapped },
    { name: 'LEAKS', query: `site:pastebin.com OR site:ghostbin.co ${wrapped}` },
    { name: 'DOCUMENTS', query: `ext:pdf OR ext:txt OR ext:csv OR ext:sql ${wrapped}` },
  ];

  const allResults = [];
  for (const dork of dorks) {
    const partial = await executeDuckDuckGoQuery(dork.query, safeTerm, dork.name);
    allResults.push(...partial);
  }

  const unique = [];
  const seen = new Set();
  for (const result of allResults) {
    const key = `${result.dorkType}|${result.url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({
      ...result,
      term: safeTerm,
      termType: type,
    });
  }

  log.info(`Dork Engine retornou ${unique.length} resultados avançados para "${safeTerm}".`);
  return unique;
}

export async function searchDorks(term) {
  return executeAdvancedDorks(term, 'username');
}
