/**
 * OSINT Hunter v2.0 — Correlation Engine
 * Analisa os resultados, cruza informações e gera um score de presença digital
 */

import { CONFIDENCE } from './engine.js';
import { getLogger } from './logger.js';

const log = getLogger('CORRELATOR');

/**
 * Calcula o score de presença digital (0-100)
 */
export function calculatePresenceScore(results) {
  let score = 0;
  let multiplier = 1.0;

  const found = results.filter(r => r.found && !r.error && !r.skipped);

  for (const r of found) {
    if (r.confidence === CONFIDENCE.HIGH) {
      score += 3;
    } else if (r.confidence === CONFIDENCE.MEDIUM) {
      score += 1.5;
    } else {
      score += 0.5;
    }
  }

  // Bônus se tiver presença em redes de alto peso (Developer, Financial)
  const categories = new Set(found.map(r => r.category || 'Outros'));
  if (categories.has('Developer')) multiplier += 0.1;
  if (categories.has('Financial')) multiplier += 0.15;
  if (categories.has('Security')) multiplier += 0.2;
  
  // Diversidade (estar em várias categorias diferentes aumenta o score)
  multiplier += (categories.size * 0.05);

  let finalScore = Math.min(Math.round(score * multiplier), 100);
  return finalScore;
}

/**
 * Cruza informações extraídas dos perfis (nomes reais, avatars)
 */
export function analyzeMetadata(results) {
  const found = results.filter(r => r.found && r.metadata);
  
  const names = {};
  const avatars = {};
  const descriptions = [];

  for (const r of found) {
    const meta = r.metadata;
    
    // Contabiliza nomes reais encontrados
    if (meta.displayName) {
      const name = meta.displayName.toLowerCase();
      names[name] = (names[name] || 0) + 1;
    }

    // Contabiliza avatars
    if (meta.avatar) {
      avatars[meta.avatar] = (avatars[meta.avatar] || 0) + 1;
    }

    if (meta.description) {
      descriptions.push({ site: r.site, text: meta.description });
    }
  }

  // Ordena por maior ocorrência
  const topNames = Object.entries(names).sort((a, b) => b[1] - a[1]).map(e => e[0]);
  const topAvatars = Object.entries(avatars).sort((a, b) => b[1] - a[1]).map(e => e[0]);

  return {
    inferredNames: topNames,
    commonAvatars: topAvatars,
    bioSnippets: descriptions,
  };
}

/**
 * Sinais comportamentais e operacionais inferidos do footprint digital
 */
export function analyzeBehavioralSignals(username, results, metadataAnalysis) {
  const found = results.filter(r => r.found && !r.error && !r.skipped);
  const categoryCount = {};
  const flags = [];
  const recommendations = [];

  for (const r of found) {
    const key = r.category || 'Outros';
    categoryCount[key] = (categoryCount[key] || 0) + 1;
  }

  const normalizedUser = (username || '').toLowerCase();
  const opsecRegex = /(sec|opsec|anon|intel|osint|root|admin|ghost|shadow|xss|0day|malware|exploit|cyber)/i;
  if (normalizedUser.length >= 4 && opsecRegex.test(normalizedUser)) {
    flags.push({
      type: 'HANDLE_OPSEC',
      severity: 'MEDIUM',
      message: 'Username com padrões semânticos ligados a segurança/opsec',
    });
  }

  const bioText = (metadataAnalysis.bioSnippets || [])
    .map(b => (b.text || '').toLowerCase())
    .join(' || ');

  const suspiciousKeywords = [
    'crypto wallet', 'telegram', 'signal', 'offshore', 'vpn',
    'drops', 'leaks', 'breach', 'marketplace', 'arsenal', 'carding',
    'fraud', 'hacker', 'hacktivist', 'stealer', 'ransomware', 'botnet'
  ];
  const matchedKeywords = suspiciousKeywords.filter(k => bioText.includes(k));

  if (matchedKeywords.length > 0) {
    flags.push({
      type: 'BIO_KEYWORDS',
      severity: matchedKeywords.length >= 3 ? 'HIGH' : 'MEDIUM',
      message: `Termos sensíveis detectados em bios: ${matchedKeywords.slice(0, 5).join(', ')}`,
    });
  }

  if ((categoryCount.Security || 0) >= 2) {
    flags.push({
      type: 'SECURITY_PRESENCE',
      severity: 'MEDIUM',
      message: 'Presença recorrente em plataformas de segurança/pesquisa técnica',
    });
  }

  if ((categoryCount.Financial || 0) >= 2) {
    flags.push({
      type: 'FINANCIAL_SURFACE',
      severity: 'HIGH',
      message: 'Exposição relevante em plataformas financeiras/fintech',
    });
  }

  if (Object.keys(categoryCount).length >= 5) {
    recommendations.push('Consolidar timeline com prioridade por categoria (Dev, Financeiro, Social, Security).');
  }
  if (flags.some(f => f.severity === 'HIGH')) {
    recommendations.push('Executar validação manual dos achados HIGH antes de qualquer decisão operacional.');
  }
  if (metadataAnalysis.commonAvatars.length > 0) {
    recommendations.push('Realizar busca reversa de imagem no avatar principal para pivoting de identidade.');
  }

  return {
    categoryCount,
    flags,
    recommendations,
  };
}

/**
 * Gera o relatório de correlação
 */
export function correlateResults(username, usernameResults, emailResults = []) {
  log.info(`Iniciando correlação de dados para o alvo: ${username}`);

  const score = calculatePresenceScore(usernameResults);
  const metadataAnalysis = analyzeMetadata(usernameResults);
  const behaviorIntel = analyzeBehavioralSignals(username, usernameResults, metadataAnalysis);
  
  // Avaliação de risco baseada no score e categorias
  let riskLevel = 'LOW';
  let profileType = 'Ghost / Inactive';

  if (score > 80) {
    riskLevel = 'CRITICAL';
    profileType = 'Highly Active Digital Footprint';
  } else if (score > 50) {
    riskLevel = 'HIGH';
    profileType = 'Active Internet User';
  } else if (score > 20) {
    riskLevel = 'MEDIUM';
    profileType = 'Casual User';
  }

  if (behaviorIntel.flags.some(f => f.severity === 'HIGH') && riskLevel !== 'CRITICAL') {
    riskLevel = riskLevel === 'LOW' ? 'MEDIUM' : 'HIGH';
  }

  // Cruzamento Email <-> Username
  let emailLinked = false;
  if (emailResults.length > 0) {
    const gitHubMatch = emailResults.find(r => r.service === 'GitHub' && r.found);
    const hasGitHubProfile = usernameResults.find(r => r.site === 'GitHub' && r.found);
    
    if (gitHubMatch && hasGitHubProfile) {
      emailLinked = true;
    }
  }

  return {
    target: username,
    presenceScore: score,
    riskLevel,
    profileType,
    metadataIntel: metadataAnalysis,
    behaviorIntel,
    emailLinked,
  };
}
