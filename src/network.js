/**
 * OSINT Hunter v2.0 — Network Manager
 * Gerenciador centralizado de requisições HTTP com suporte a proxy,
 * retry automático, rate limiting e fingerprint randomization
 */

import fetch from 'node-fetch';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { getLogger } from './logger.js';

const log = getLogger('NETWORK');

// Pool expandida de User-Agents (30+ UAs reais 2024-2026)
const USER_AGENTS = [
  // Chrome Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  // Chrome Mac
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  // Chrome Linux
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  // Firefox Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
  // Firefox Mac
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0',
  // Firefox Linux
  'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0',
  // Safari Mac
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  // Edge Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
  // Mobile
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
];

const ACCEPT_HEADERS = [
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
];

const ACCEPT_LANGUAGES = [
  'en-US,en;q=0.9',
  'en-US,en;q=0.8,en;q=0.7',
];

/**
 * Classe NetworkManager — gerencia todas as requisições HTTP da ferramenta
 */
export class NetworkManager {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.maxRetries = options.maxRetries || 2;
    this.proxyUrl = options.proxy || null;
    this.agent = null;
    this._domainTimestamps = new Map(); // Rate limiting por domínio
    this._minDomainDelay = options.domainDelay || 200; // ms entre requests ao mesmo domínio

    // Configura proxy agent se fornecido
    if (this.proxyUrl) {
      if (this.proxyUrl.startsWith('socks')) {
        this.agent = new SocksProxyAgent(this.proxyUrl);
        log.info(`Proxy SOCKS5 configurado: ${this.proxyUrl}`);
      } else {
        this.agent = new HttpsProxyAgent(this.proxyUrl);
        log.info(`Proxy HTTP/S configurado: ${this.proxyUrl}`);
      }
    }
  }

  /**
   * Gera headers randomizados para simular um navegador real
   */
  _randomHeaders(extraHeaders = {}) {
    return {
      'User-Agent': USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)],
      'Accept': ACCEPT_HEADERS[Math.floor(Math.random() * ACCEPT_HEADERS.length)],
      'Accept-Language': ACCEPT_LANGUAGES[Math.floor(Math.random() * ACCEPT_LANGUAGES.length)],
      'Accept-Encoding': 'gzip, deflate, br',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Cache-Control': 'max-age=0',
      ...extraHeaders,
    };
  }

  /**
   * Rate limiting por domínio — espera se necessário
   */
  async _rateLimitDomain(url) {
    try {
      const domain = new URL(url).hostname;
      const lastRequest = this._domainTimestamps.get(domain);
      if (lastRequest) {
        const elapsed = Date.now() - lastRequest;
        if (elapsed < this._minDomainDelay) {
          const waitTime = this._minDomainDelay - elapsed;
          await new Promise(r => setTimeout(r, waitTime));
        }
      }
      this._domainTimestamps.set(domain, Date.now());
    } catch { /* ignore invalid URLs */ }
  }

  /**
   * Executa uma requisição HTTP com retry automático e backoff exponencial
   */
  async request(url, options = {}) {
    const method = options.method || 'GET';
    const headers = this._randomHeaders(options.headers || {});
    const redirectMode = options.redirect || 'manual';

    await this._rateLimitDomain(url);

    let lastError = null;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        const fetchOptions = {
          method,
          headers,
          redirect: redirectMode,
          signal: controller.signal,
        };

        if (this.agent) {
          fetchOptions.agent = this.agent;
        }

        const response = await fetch(url, fetchOptions);
        clearTimeout(timeoutId);

        log.debug(`${method} ${url} → ${response.status}`, { attempt });
        return response;

      } catch (error) {
        lastError = error;

        if (attempt < this.maxRetries) {
          // Backoff exponencial: 1s, 2s, 4s...
          const backoff = Math.pow(2, attempt) * 1000;
          log.debug(`Retry ${attempt + 1}/${this.maxRetries} for ${url} in ${backoff}ms`);
          await new Promise(r => setTimeout(r, backoff));
        }
      }
    }

    // Todas as tentativas falharam
    const errorMsg = lastError?.name === 'AbortError'
      ? `Timeout (${this.timeout}ms)`
      : lastError?.code === 'ENOTFOUND'
        ? 'DNS Resolution Failed'
        : lastError?.code === 'ECONNREFUSED'
          ? 'Connection Refused'
          : lastError?.code === 'ECONNRESET'
            ? 'Connection Reset'
            : lastError?.message || 'Unknown Error';

    log.debug(`FAILED ${url}: ${errorMsg}`);
    throw new Error(errorMsg);
  }

  /**
   * GET simplificado
   */
  async get(url, options = {}) {
    return this.request(url, { ...options, method: 'GET' });
  }

  /**
   * HEAD simplificado
   */
  async head(url, options = {}) {
    return this.request(url, { ...options, method: 'HEAD' });
  }

  /**
   * GET que retorna o body como texto
   */
  async getText(url, options = {}) {
    const response = await this.get(url, options);
    return { response, body: await response.text() };
  }

  /**
   * GET que retorna o body como JSON
   */
  async getJSON(url, options = {}) {
    const response = await this.get(url, {
      ...options,
      headers: { 'Accept': 'application/json', ...(options.headers || {}) },
    });
    return { response, data: await response.json() };
  }
}

// Instância global
let _networkInstance = null;

export function initNetwork(options = {}) {
  _networkInstance = new NetworkManager(options);
  return _networkInstance;
}

export function getNetwork() {
  if (!_networkInstance) {
    _networkInstance = new NetworkManager();
  }
  return _networkInstance;
}
