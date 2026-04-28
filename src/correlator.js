/**
 * OSINT Hunter v2.0 — Correlation Engine
 * Analisa os resultados, cruza informações e gera um score de presença digital
 */

import { CONFIDENCE } from './engine.js';
import { getLogger } from './logger.js';
import { getConfig } from './config.js';

const log = getLogger('CORRELATOR');

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

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
  const config = getConfig();
  const minKeywordHits = Math.max(1, config.intelligence?.minKeywordHits ?? 1);
  const highConfidenceOnly = config.intelligence?.highConfidenceOnly ?? true;
  const suspiciousKeywords = config.intelligence?.suspiciousKeywords || [
    'crypto wallet', 'telegram', 'signal', 'offshore', 'vpn',
    'drops', 'leaks', 'breach', 'marketplace', 'arsenal', 'carding',
    'fraud', 'hacker', 'hacktivist', 'stealer', 'ransomware', 'botnet'
  ];

  const found = results.filter((r) => {
    if (!r.found || r.error || r.skipped) return false;
    if (!highConfidenceOnly) return true;
    return r.confidence === CONFIDENCE.HIGH || r.confidence === CONFIDENCE.MEDIUM;
  });
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

  const matchedKeywords = suspiciousKeywords.filter((k) => {
    const pattern = new RegExp(`(^|\\W)${escapeRegex(String(k).toLowerCase())}(\\W|$)`, 'i');
    return pattern.test(bioText);
  });

  if (matchedKeywords.length >= minKeywordHits) {
    flags.push({
      type: 'BIO_KEYWORDS',
      severity: matchedKeywords.length >= 3 ? 'HIGH' : 'MEDIUM',
      message: `Termos sensíveis detectados em bios: ${matchedKeywords.slice(0, 5).join(', ')}`,
      evidence: `${matchedKeywords.length} termos detectados em metadados de perfil`,
    });
  }

  if ((categoryCount.Security || 0) >= 2) {
    flags.push({
      type: 'SECURITY_PRESENCE',
      severity: 'MEDIUM',
      message: 'Presença recorrente em plataformas de segurança/pesquisa técnica',
      evidence: `Ocorrências na categoria Security: ${categoryCount.Security}`,
    });
  }

  if ((categoryCount.Financial || 0) >= 2) {
    flags.push({
      type: 'FINANCIAL_SURFACE',
      severity: 'HIGH',
      message: 'Exposição relevante em plataformas financeiras/fintech',
      evidence: `Ocorrências na categoria Financial: ${categoryCount.Financial}`,
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
  if (metadataAnalysis.inferredNames.length > 0) {
    recommendations.push(`DEEP HUNT: Nome real detectado ("${metadataAnalysis.inferredNames[0]}"). Rode a ferramenta novamente com variações deste nome para achar contas desconectadas do username atual.`);
  }
  if (highConfidenceOnly) {
    recommendations.push('Reexecutar scan com --verbose para validar bloqueios e aumentar cobertura de evidências.');
  }

  return {
    categoryCount,
    flags,
    recommendations,
  };
}

function calculateBehaviorScore(behaviorIntel) {
  let score = 0;
  for (const flag of behaviorIntel.flags) {
    if (flag.severity === 'HIGH') score += 30;
    else if (flag.severity === 'MEDIUM') score += 15;
    else score += 5;
  }

  const categoryDiversity = Object.keys(behaviorIntel.categoryCount || {}).length;
  score += Math.min(categoryDiversity * 4, 20);

  if (behaviorIntel.recommendations.length >= 2) {
    score += 10;
  }

  return Math.min(score, 100);
}

function buildEvidenceTrail(behaviorIntel, metadataAnalysis) {
  const evidence = [];
  for (const flag of behaviorIntel.flags) {
    evidence.push(`${flag.type}: ${flag.message}${flag.evidence ? ` (${flag.evidence})` : ''}`);
  }
  if (metadataAnalysis.inferredNames.length > 0) {
    evidence.push(`Nomes inferidos consistentes: ${metadataAnalysis.inferredNames.slice(0, 3).join(', ')}`);
  }
  if (Object.keys(behaviorIntel.categoryCount || {}).length > 0) {
    evidence.push(`Diversidade de categorias: ${Object.keys(behaviorIntel.categoryCount).length}`);
  }
  return evidence;
}

/**
 * Gera o relatório de correlação
 */
export function correlateResults(username, usernameResults, emailResults = []) {
  log.info(`Iniciando correlação de dados para o alvo: ${username}`);
  const config = getConfig();
  const behaviorWeight = Math.max(0, Math.min(1, config.intelligence?.behaviorWeight ?? 0.4));
  const criticalRiskThreshold = config.intelligence?.criticalRiskThreshold ?? 90;
  const highRiskThreshold = config.intelligence?.highRiskThreshold ?? 75;

  const score = calculatePresenceScore(usernameResults);
  const metadataAnalysis = analyzeMetadata(usernameResults);
  const behaviorIntel = analyzeBehavioralSignals(username, usernameResults, metadataAnalysis);
  const behaviorScore = calculateBehaviorScore(behaviorIntel);
  const finalScore = Math.round((score * (1 - behaviorWeight)) + (behaviorScore * behaviorWeight));
  const evidenceTrail = buildEvidenceTrail(behaviorIntel, metadataAnalysis);
  const intelligenceConfidence = Math.min(
    100,
    (behaviorIntel.flags.length * 20) +
    (metadataAnalysis.inferredNames.length > 0 ? 15 : 0) +
    (Object.keys(behaviorIntel.categoryCount).length * 5)
  );
  
  // Avaliação de risco baseada no score e categorias
  let riskLevel = 'LOW';
  let profileType = 'Ghost / Inactive';

  if (finalScore >= criticalRiskThreshold) {
    riskLevel = 'CRITICAL';
    profileType = 'Highly Active Digital Footprint';
  } else if (finalScore >= highRiskThreshold) {
    riskLevel = 'HIGH';
    profileType = 'Active Internet User';
  } else if (finalScore > 35) {
    riskLevel = 'MEDIUM';
    profileType = 'Casual User';
  }

  if (behaviorIntel.flags.some(f => f.severity === 'HIGH') && riskLevel === 'LOW') {
    riskLevel = 'MEDIUM';
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
    finalRiskScore: finalScore,
    behaviorScore,
    riskLevel,
    profileType,
    metadataIntel: metadataAnalysis,
    behaviorIntel,
    evidenceTrail,
    intelligenceConfidence,
    emailLinked,
  };
}
