/**
 * OSINT Hunter v2.0 — Username Search Engine
 * Motor de busca profissional com 5 métodos de detecção,
 * classificação de confiança, e extração de metadados
 */

import pLimit from 'p-limit';
import { getNetwork } from './network.js';
import { getLogger } from './logger.js';

const log = getLogger('ENGINE');

// Controle de concorrência
const DEFAULT_CONCURRENCY = 20;

/**
 * Níveis de confiança do resultado
 */
export const CONFIDENCE = {
  HIGH: 'HIGH',       // Status code + conteúdo validado
  MEDIUM: 'MEDIUM',   // Apenas status code
  LOW: 'LOW',         // Resultado incerto (redirect ambíguo, etc.)
};

/**
 * Valida se o username é válido para uma plataforma específica
 */
function isValidUsername(username, site) {
  if (!site.regexCheck) return true;
  try {
    const regex = new RegExp(site.regexCheck);
    return regex.test(username);
  } catch {
    return true; // Se a regex for inválida, prossegue
  }
}

/**
 * Tenta extrair metadados básicos do HTML do perfil
 */
function extractMetadata(body, url) {
  if (!body || typeof body !== 'string') return null;

  const metadata = {};

  // Extrai título da página
  const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (titleMatch) metadata.pageTitle = titleMatch[1].trim();

  // Extrai meta description
  const descMatch = body.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i);
  if (descMatch) metadata.description = descMatch[1].trim();

  // Extrai avatar/foto de perfil (Open Graph)
  const ogImageMatch = body.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']+)["']/i);
  if (ogImageMatch) metadata.avatar = ogImageMatch[1];

  // Extrai nome real (Open Graph title)
  const ogTitleMatch = body.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i);
  if (ogTitleMatch) metadata.displayName = ogTitleMatch[1].trim();

  // Extrai Open Graph type
  const ogTypeMatch = body.match(/<meta[^>]*property=["']og:type["'][^>]*content=["']([^"']+)["']/i);
  if (ogTypeMatch) metadata.ogType = ogTypeMatch[1];

  return Object.keys(metadata).length > 0 ? metadata : null;
}

/**
 * Validação Estrita de Perfil (Web Scraping)
 * Garante que o username aparece no HTML da página para zerar Falsos Positivos.
 */
function validateProfileContent(body, username, metadata) {
  if (!body) return false;
  
  const lowerUser = username.toLowerCase();
  
  // 1. Checa nos metadados extraídos (Title, Description, OG Title)
  if (metadata) {
    if (metadata.pageTitle && metadata.pageTitle.toLowerCase().includes(lowerUser)) return true;
    if (metadata.displayName && metadata.displayName.toLowerCase().includes(lowerUser)) return true;
    if (metadata.description && metadata.description.toLowerCase().includes(lowerUser)) return true;
  }
  
  // 2. Fallback para SPAs puros (Instagram, Spotify, etc)
  // Sites onde o Title é cego (ex: "Instagram") mas o body cru contém as informações em JSON ou JS embutido.
  // Precisamos ser rigorosos para não pegar reflexões de URL em páginas 404.
  const bodyLower = body.toLowerCase();
  
  // Para minimizar Falso Positivo (que era o problema do "raw body" antes),
  // buscamos o username APENAS se estiver associado a uma chave semântica em JSON ou Objeto JS
  // ex: "username":"malheirosan", username:"malheirosan", "alternateName":"malheirosan"
  const jsonPattern = new RegExp(`['"]?(?:user|username|name|alternateName|screen_name|handle|id)['"]?\\s*:\\s*['"]${username}['"]`, 'i');
  if (jsonPattern.test(body)) {
    // Checagem anti-falso-positivo: se a página tiver assinaturas clássicas de 404/Soft404
    if (
      bodyLower.includes("page not found") || 
      bodyLower.includes("couldn't find the page") ||
      bodyLower.includes("doesn't exist") ||
      bodyLower.includes("the link you followed may be broken") ||
      bodyLower.includes("this page isn't available") ||
      bodyLower.includes("this account doesn't exist")
    ) {
      return false; 
    }
    return true;
  }
  // 3. Exceções Seguras para Single Page Applications (SPAs) Específicas
  // O Instagram retorna 404 puro (sem 200 disfarçado) quando o perfil não existe.
  // Logo, se ele retornar 200 OK, e tivermos as tags base do Instagram, podemos confiar que o perfil existe,
  // mesmo que o username esteja ofuscado no React State e falhe no jsonPattern.
  if (bodyLower.includes('<title>instagram</title>') || bodyLower.includes('content="instagram"')) {
      if (!bodyLower.includes("httperrorpage")) {
          return true;
      }
  }

  // O Spotify também ofusca severamente as páginas, mas retorna meta tags descritivas em alguns casos,
  // ou pode ser validado pela ausência de erro "page not found" em um 200 OK.
  if (bodyLower.includes('<title>spotify') && !bodyLower.includes('page not found')) {
      // Como o Spotify é vulnerável a soft 404s em algumas regiões, validamos pela presença do ID de usuário longo que eles usam,
      // ou apenas pela tag estrutural de perfil.
      if (bodyLower.includes('content="profile"')) {
         return true;
      }
  }

  // O Snapchat tem um padrão de URL muito forte que não reflete contas falsas.
  if (bodyLower.includes('histórias, holofote e lentes do snapchat') || bodyLower.includes('is on snapchat!')) {
      return true;
  }

  // Se não encontrou de nenhuma forma estruturada (Metadados ou JSON/JS),
  // assumimos Falso Positivo. SPAs rigorosas que bloqueiam regex
  // exigirão a implementação de Headless Browsing em versões futuras, 
  // mas aqui priorizamos a Precisão Zero Falsos Positivos.
  return false;
}

/**
 * Verifica se um username existe em um site específico
 */
async function checkSite(username, site, network) {
  const url = (site.urlProbe || site.url).replace(/\{\}|\{username\}/g, encodeURIComponent(username));
  const profileUrl = site.url.replace(/\{\}|\{username\}/g, encodeURIComponent(username));
  const startTime = Date.now();

  // Validação de regex antes de fazer a requisição
  if (!isValidUsername(username, site)) {
    return {
      site: site.name,
      category: site.category || 'Outros',
      url: profileUrl,
      found: false,
      confidence: null,
      statusCode: null,
      responseTime: 0,
      metadata: null,
      error: 'Username inválido para esta plataforma',
      skipped: true,
    };
  }

  try {
    const response = await network.get(url, {
      headers: site.headers || {},
      redirect: 'manual',
    });

    const elapsed = Date.now() - startTime;
    let found = false;
    let confidence = CONFIDENCE.MEDIUM;
    let body = null;
    let metadata = null;

    switch (site.method || site.errorType) {
      // ═══ Método 1: Status Code ═══
      case 'status_code': {
        const expectedError = site.errorCode || 404;
        found = response.status !== expectedError && response.status >= 200 && response.status < 400;
        confidence = found ? CONFIDENCE.MEDIUM : CONFIDENCE.HIGH;
        if (found && response.status === 200) {
          body = await response.text();
        }
        break;
      }

      // ═══ Método 2: Message (busca string no body) ═══
      case 'message': {
        body = await response.text();
        const errorMessages = Array.isArray(site.errorMsg || site.errorMessage)
          ? (site.errorMsg || site.errorMessage)
          : [site.errorMsg || site.errorMessage];

        const hasError = errorMessages.some(msg => msg && body.includes(msg));
        found = !hasError && response.status < 400;
        confidence = found ? CONFIDENCE.HIGH : CONFIDENCE.HIGH; // Ambos são alta confiança
        break;
      }

      // ═══ Método 3: Redirect / Response URL ═══
      case 'redirect':
      case 'response_url': {
        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get('location') || '';
          const errorUrl = site.errorUrl || '/error';
          found = !location.includes(errorUrl);
          confidence = found ? CONFIDENCE.LOW : CONFIDENCE.MEDIUM;
        } else {
          found = response.status >= 200 && response.status < 300;
          confidence = found ? CONFIDENCE.MEDIUM : CONFIDENCE.MEDIUM;
        }
        break;
      }

      // ═══ Método 4: Regex no Body ═══
      case 'regex_body': {
        body = await response.text();
        if (site.regexMatch) {
          try {
            const regex = new RegExp(site.regexMatch, 'i');
            found = regex.test(body);
            confidence = found ? CONFIDENCE.HIGH : CONFIDENCE.HIGH;
          } catch {
            found = response.status === 200;
            confidence = CONFIDENCE.LOW;
          }
        }
        break;
      }

      // ═══ Método 5: API Probe (JSON response) ═══
      case 'api_probe': {
        if (response.status === 200) {
          try {
            const json = await response.json();
            found = site.jsonKey ? !!json[site.jsonKey] : true;
            confidence = CONFIDENCE.HIGH;
          } catch {
            found = false;
            confidence = CONFIDENCE.LOW;
          }
        }
        break;
      }

      // ═══ Default ═══
      default: {
        found = response.status >= 200 && response.status < 300;
        if (found) body = await response.text();
        break;
      }
    }

    // --- GLOBAL SOFT 404 DETECTION ---
    // Mesmo que o site retorne 200 (como OnlyFans, Pornhub, TikTok, etc), o conteúdo 
    // pode indicar que o usuário não existe. 
    if (found) {
      // 1. Verificação Global de Redirecionamento (URL Mismatch)
      // Se a URL final (após redirects) não contiver o username procurado, provavelmente caiu na home ou login
      const finalUrl = response.url.toLowerCase();
      const lowerUser = username.toLowerCase();
      
      // Ignora parâmetros de query e trailing slashes para a comparação
      let cleanFinalUrl = finalUrl.split('?')[0];
      if (cleanFinalUrl.endsWith('/')) cleanFinalUrl = cleanFinalUrl.slice(0, -1);
      
      let expectedUrl = url.toLowerCase().split('?')[0];
      if (expectedUrl.endsWith('/')) expectedUrl = expectedUrl.slice(0, -1);
      
      if (cleanFinalUrl !== expectedUrl) {
        // Se a URL final não tiver o username, é um redirect falso (ex: login, index)
        if (!cleanFinalUrl.includes(lowerUser)) {
          found = false;
          confidence = CONFIDENCE.HIGH;
        }
      }

      // 2. Verificação de Conteúdo (Signatures)
      if (found && body) {
        const soft404Signatures = [
          "page not found",
          "user not found",
          "could not find that user",
          "sorry, that page doesn't exist",
          "this page isn't available",
          "this account doesn't exist",
          "404 not found",
          "the page you requested could not be found",
          "the specified profile could not be found",
          "centralauth-admin-nonexistent",
          "user does not exist",
          "no users found",
          "content not found",
          "profile not found",
          "we couldn't find the page",
          "the page you're looking for",
          "page you are looking for",
          "404 error",
          "error 404",
          "nothing to see here",
          "doesn't exist or has been deleted",
          "hasn't been created yet",
          "deviantart: 404"
        ];
        const lowerBody = body.toLowerCase();
        const isSoft404 = soft404Signatures.some(sig => lowerBody.includes(sig));
        
        // Checa também se fomos bloqueados (Cloudflare/CAPTCHA)
        const isBlocked = lowerBody.includes("enable javascript and cookies to continue") || lowerBody.includes("cloudflare") || lowerBody.includes("attention required!");

        if (isSoft404) {
          found = false;
          confidence = CONFIDENCE.HIGH; // Temos certeza que não existe
        } else if (isBlocked) {
          found = false;
          confidence = null; // Falso negativo por bloqueio de WAF
          log.debug('Bloqueio de WAF/Cloudflare detectado em: ' + site.name);
        }
      }
    }

    // Tenta extrair metadados do HTML apenas se o perfil estiver marcado como encontrado
    if (found) {
      if (!body) {
        try { body = await response.text(); } catch { /* ignore */ }
      }
      
      metadata = extractMetadata(body, profileUrl);
        
        // --- STRICT PROFILE VALIDATION (WEB SCRAPING) ---
        // Exige que o username seja comprovadamente mencionado nos metadados ou no body.
        // Ignora checagem estrita para api_probe pois não possuem HTML estruturado.
        if (site.method !== 'api_probe') {
          const isValidProfile = validateProfileContent(body, username, metadata);
          if (!isValidProfile) {
            found = false;
            confidence = null; // Falso positivo descartado pelo validador estrito
            log.debug(`Scraping Estrito: Username não encontrado no HTML de ${site.name}`);
          }
        }
      }

    return {
      site: site.name,
      category: site.category || 'Outros',
      url: profileUrl,
      found,
      confidence,
      statusCode: response.status,
      responseTime: elapsed,
      metadata,
      error: null,
      skipped: false,
      isNSFW: site.isNSFW || false,
      tags: site.tags || [],
    };

  } catch (error) {
    const elapsed = Date.now() - startTime;
    return {
      site: site.name,
      category: site.category || 'Outros',
      url: profileUrl,
      found: false,
      confidence: null,
      statusCode: null,
      responseTime: elapsed,
      metadata: null,
      error: error.message,
      skipped: false,
      isNSFW: site.isNSFW || false,
      tags: site.tags || [],
    };
  }
}

/**
 * Executa a busca de um username em todas as plataformas
 */
export async function searchUsername(username, sites, options = {}) {
  const {
    onResult = null,
    concurrency = DEFAULT_CONCURRENCY,
    includeNSFW = false,
    filterCategory = null,
  } = options;

  const network = getNetwork();
  const limit = pLimit(concurrency);

  // Filtra sites
  let filteredSites = sites;
  if (!includeNSFW) {
    filteredSites = filteredSites.filter(s => !s.isNSFW);
  }
  if (filterCategory) {
    const cat = filterCategory.toLowerCase();
    filteredSites = filteredSites.filter(s => (s.category || '').toLowerCase().includes(cat));
  }

  log.info(`Iniciando busca por "${username}" em ${filteredSites.length} plataformas (concurrency: ${concurrency})`);

  const tasks = filteredSites.map(site =>
    limit(async () => {
      const result = await checkSite(username, site, network);
      if (onResult) onResult(result);
      return result;
    })
  );

  const results = await Promise.all(tasks);

  const found = results.filter(r => r.found && !r.error);
  const errors = results.filter(r => r.error);
  const skipped = results.filter(r => r.skipped);

  log.info(`Busca concluída: ${found.length} encontrados, ${errors.length} erros, ${skipped.length} pulados`);

  return results;
}

/**
 * Funções de filtragem de resultados
 */
export function getFoundResults(results) {
  return results.filter(r => r.found && !r.error);
}

export function getErrorResults(results) {
  return results.filter(r => r.error !== null);
}

export function getHighConfidenceResults(results) {
  return results.filter(r => r.found && r.confidence === CONFIDENCE.HIGH);
}

export function groupByCategory(results) {
  const groups = {};
  for (const r of results) {
    const cat = r.category || 'Outros';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(r);
  }
  return groups;
}

export function groupByConfidence(results) {
  return {
    [CONFIDENCE.HIGH]: results.filter(r => r.found && r.confidence === CONFIDENCE.HIGH),
    [CONFIDENCE.MEDIUM]: results.filter(r => r.found && r.confidence === CONFIDENCE.MEDIUM),
    [CONFIDENCE.LOW]: results.filter(r => r.found && r.confidence === CONFIDENCE.LOW),
  };
}
