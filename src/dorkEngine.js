/**
 * OSINT Hunter v3.0 — Dynamic Dork Engine (Search Engine Scraping)
 * Vasculha a internet livre (via DuckDuckGo) por qualquer menção ao username alvo.
 */

import { getNetwork } from './network.js';
import { getLogger } from './logger.js';
import { extractDomainFromEmail } from './utils.js'; // Reaproveitando lógica de domínio

const log = getLogger('DORK_ENGINE');

export async function searchDorks(username) {
  log.info(`Iniciando Search Engine Scraping (Dorking) para: "${username}"`);
  const network = getNetwork();
  const query = encodeURIComponent(`"${username}"`);
  const url = `https://html.duckduckgo.com/html/?q=${query}`;

  try {
    // Faremos o request tentando simular um navegador comum o máximo possível
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

    // DuckDuckGo HTML Lite usa class="result__url"
    // <a class="result__url" href="//duckduckgo.com/l/?uddg=https://example.com/malheirosan">
    const urlRegex = /<a[^>]+class="result__url"[^>]+href="([^"]+)"/ig;
    let match;
    const rawLinks = [];

    while ((match = urlRegex.exec(html)) !== null) {
      let extractedUrl = match[1];
      
      // DuckDuckGo encapsula o link de destino no parâmetro `uddg`
      if (extractedUrl.includes('uddg=')) {
        try {
          const urlObj = new URL('https:' + extractedUrl);
          const actualLink = urlObj.searchParams.get('uddg');
          if (actualLink) {
            rawLinks.push(decodeURIComponent(actualLink));
          }
        } catch {
          // Ignora falhas de parsing
        }
      } else {
        // Fallback caso não esteja com o wrapper
        rawLinks.push(extractedUrl);
      }
    }

    // Filtra e limpa os links
    const uniqueLinks = [...new Set(rawLinks)];
    const validProfiles = [];

    for (const link of uniqueLinks) {
        // Limpa parâmetros inúteis na URL se existirem para rastreamento
        let cleanLink = link.split('?')[0];

        // Vamos extrair o domínio para facilitar a leitura
        let domain = 'Unknown';
        try {
            domain = new URL(cleanLink).hostname.replace('www.', '');
        } catch { }

        // Se o username estiver na URL exata ou o link contiver menções fortes
        if (cleanLink.toLowerCase().includes(username.toLowerCase())) {
            validProfiles.push({
                domain,
                url: link, // salva o link original
                source: 'DuckDuckGo',
                confidence: 'HIGH',
            });
        } else {
             validProfiles.push({
                domain,
                url: link,
                source: 'DuckDuckGo',
                confidence: 'MEDIUM', // Achou a string dentro do conteúdo da página, mas não na URL
            });
        }
    }

    log.info(`Dork Engine encontrou ${validProfiles.length} resultados dinâmicos no DuckDuckGo.`);
    return validProfiles;

  } catch (error) {
    log.error(`Falha no Dork Engine: ${error.message}`);
    return [];
  }
}
