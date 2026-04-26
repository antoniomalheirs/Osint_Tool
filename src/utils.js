/**
 * OSINT Hunter v2.0 — Utility Module
 * Helpers profissionais para hashing, formatação, e variações de username
 */

import crypto from 'node:crypto';

/**
 * Gera hash MD5 (usado para Gravatar)
 */
export function md5(str) {
  return crypto.createHash('md5').update(str.trim().toLowerCase()).digest('hex');
}

/**
 * Gera hash SHA1 (usado para HIBP k-Anonymity)
 */
export function sha1(str) {
  return crypto.createHash('sha1').update(str.trim()).digest('hex').toUpperCase();
}

/**
 * Gera hash SHA256
 */
export function sha256(str) {
  return crypto.createHash('sha256').update(str.trim().toLowerCase()).digest('hex');
}

/**
 * Extrai o username de um endereço de e-mail
 */
export function extractUsernameFromEmail(email) {
  if (!email || !email.includes('@')) return null;
  return email.split('@')[0];
}

/**
 * Extrai o domínio de um e-mail
 */
export function extractDomainFromEmail(email) {
  if (!email || !email.includes('@')) return null;
  return email.split('@')[1].toLowerCase();
}

/**
 * Gera variações inteligentes de username a partir de um e-mail
 */
export function generateUsernameVariations(email) {
  const base = extractUsernameFromEmail(email);
  if (!base) return [];

  const variations = new Set();
  variations.add(base); // original

  // Remove separadores
  variations.add(base.replace(/[.\-_]/g, ''));

  // Pontos → underscores
  variations.add(base.replace(/\./g, '_'));

  // Pontos → hífens
  variations.add(base.replace(/\./g, '-'));

  // Underscores → pontos
  variations.add(base.replace(/_/g, '.'));

  // Hífens → underscores
  variations.add(base.replace(/-/g, '_'));

  // Remove números (se ainda tiver 3+ chars)
  const noNumbers = base.replace(/[0-9]/g, '');
  if (noNumbers.length >= 3) variations.add(noNumbers);

  // Apenas a parte antes de números finais (ex: john123 → john)
  const baseNoTrailingNums = base.replace(/[0-9]+$/, '');
  if (baseNoTrailingNums.length >= 3) variations.add(baseNoTrailingNums);

  // Se tem ponto, tenta nome.sobrenome → nomesobrenome, nome_sobrenome
  if (base.includes('.')) {
    const parts = base.split('.');
    if (parts.length === 2) {
      variations.add(parts[0]); // apenas primeiro nome
      variations.add(parts.join(''));
      variations.add(parts.join('_'));
      variations.add(parts.join('-'));
      // Iniciais: j.doe → jdoe
      variations.add(parts[0][0] + parts[1]);
    }
  }

  return [...variations].filter(v => v && v.length >= 2);
}

/**
 * Valida se uma string é um e-mail
 */
export function isEmail(input) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
}

/**
 * Valida se parece ser um domínio
 */
export function isDomain(input) {
  return /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(input) && !input.includes('@');
}

/**
 * Formata duração em ms para string legível
 */
export function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = ((ms % 60000) / 1000).toFixed(0);
  return `${minutes}m ${seconds}s`;
}

/**
 * Trunca string
 */
export function truncate(str, maxLen = 50) {
  if (!str) return '';
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + '...';
}

/**
 * Delay assíncrono
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Formata timestamp ISO para exibição
 */
export function formatTimestamp(isoString) {
  return new Date(isoString).toLocaleString('pt-BR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}
