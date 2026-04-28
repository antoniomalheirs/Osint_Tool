/**
 * OSINT Hunter v2.0 — SMTP Validation Module
 * Verifica se a caixa de entrada existe comunicando-se diretamente com os servidores MX.
 */

import net from 'node:net';
import { getMXRecords } from './dnsIntel.js';
import { extractDomainFromEmail } from './utils.js';
import { getLogger } from './logger.js';

const log = getLogger('SMTP_VALIDATION');

/**
 * Conecta a um servidor SMTP e verifica o e-mail via protocolo TCP
 */
async function checkMailboxOnServer(email, mxHost) {
  const domain = extractDomainFromEmail(email);
  return new Promise((resolve) => {
    let stage = 0;
    let found = null;
    let reason = 'Connection closed or timeout';
    let info = '';

    const socket = new net.Socket();
    const timeout = 6000; // 6 segundos de timeout

    socket.setTimeout(timeout);

    const cleanup = () => {
      if (!socket.destroyed) {
        socket.end();
        socket.destroy();
      }
    };

    socket.on('timeout', () => {
      reason = 'SMTP connection timeout';
      log.debug(`SMTP Timeout for ${mxHost}`);
      cleanup();
      resolve({ valid: null, info: 'Timeout na conexão SMTP', reason: 'TIMEOUT' });
    });

    socket.on('error', (err) => {
      reason = `SMTP error: ${err.message}`;
      log.debug(`SMTP Error on ${mxHost}: ${err.message}`);
      cleanup();
      resolve({ valid: null, info: `Erro na conexão SMTP: ${err.message}`, reason: 'ERROR' });
    });

    socket.on('data', (data) => {
      const res = data.toString();
      log.debug(`[SMTP] <-- ${res.trim()}`);

      // Em alguns casos o servidor envia múltiplas linhas
      const lines = res.split('\r\n').filter(l => l.trim() !== '');
      const lastLine = lines[lines.length - 1];

      if (lastLine.startsWith('220') && stage === 0) {
        // Welcome message, send HELO
        stage = 1;
        const cmd = `HELO ${domain}\r\n`;
        log.debug(`[SMTP] --> ${cmd.trim()}`);
        socket.write(cmd);
      } else if (lastLine.startsWith('250') && stage === 1) {
        // HELO accepted, send MAIL FROM
        stage = 2;
        const cmd = `MAIL FROM:<verify@${domain}>\r\n`;
        log.debug(`[SMTP] --> ${cmd.trim()}`);
        socket.write(cmd);
      } else if (lastLine.startsWith('250') && stage === 2) {
        // MAIL FROM accepted, send RCPT TO
        stage = 3;
        const cmd = `RCPT TO:<${email}>\r\n`;
        log.debug(`[SMTP] --> ${cmd.trim()}`);
        socket.write(cmd);
      } else if (stage === 3) {
        // Handle RCPT TO response
        if (lastLine.startsWith('250')) {
          found = true;
          info = 'Caixa de entrada confirmada pelo servidor';
          reason = 'BOX_EXISTS';
        } else if (lastLine.startsWith('550') || lastLine.startsWith('553') || lastLine.startsWith('551') || lastLine.startsWith('511')) {
          found = false;
          info = `Servidor rejeitou o endereço: ${lastLine.trim()}`;
          reason = 'BOX_NOT_FOUND';
        } else if (lastLine.startsWith('450') || lastLine.startsWith('451') || lastLine.startsWith('452')) {
          found = null;
          info = 'Servidor temporariamente indisponível ou rate limit (Greylisting)';
          reason = 'GREYLISTING_OR_RATE_LIMIT';
        } else {
          found = null;
          info = `Resposta inesperada: ${lastLine.trim()}`;
          reason = 'UNKNOWN_RESPONSE';
        }
        
        // Finaliza enviando QUIT
        const cmd = 'QUIT\r\n';
        log.debug(`[SMTP] --> ${cmd.trim()}`);
        socket.write(cmd);
        cleanup();
        resolve({ valid: found, info, reason, rawResponse: lastLine.trim() });
      } else if (stage > 0 && (lastLine.startsWith('5') || lastLine.startsWith('4'))) {
        // Se houver recusa nas etapas iniciais (HELO ou MAIL FROM)
        found = null;
        info = `Bloqueado antes do RCPT TO: ${lastLine.trim()}`;
        reason = 'BLOCKED_EARLY';
        
        const cmd = 'QUIT\r\n';
        socket.write(cmd);
        cleanup();
        resolve({ valid: found, info, reason, rawResponse: lastLine.trim() });
      }
    });

    socket.on('close', () => {
      if (found === null && reason !== 'TIMEOUT' && reason !== 'ERROR' && reason !== 'BLOCKED_EARLY') {
         resolve({ valid: null, info: 'Conexão encerrada antes da conclusão', reason: 'CONNECTION_CLOSED' });
      }
    });

    log.debug(`Connecting to ${mxHost}:25`);
    socket.connect(25, mxHost);
  });
}

/**
 * Executa validação de caixa de entrada consultando os MXs do domínio
 */
export async function validateEmailSmtp(email) {
  const domain = extractDomainFromEmail(email);
  if (!domain) return { error: 'E-mail inválido' };

  log.info(`Iniciando validação SMTP para ${email}`);

  const mxRecords = await getMXRecords(domain);
  if (!mxRecords || mxRecords.length === 0) {
    return {
      service: 'SMTP Validation',
      found: null,
      url: null,
      info: 'Nenhum servidor MX encontrado para o domínio',
      reason: 'NO_MX_RECORDS'
    };
  }

  // Tenta conectar no MX primário primeiro, depois no secundário se falhar
  for (const mx of mxRecords) {
    log.info(`Tentando validação SMTP no servidor: ${mx.exchange}`);
    const result = await checkMailboxOnServer(email, mx.exchange);
    
    // Se obteve uma resposta definitiva (true ou false) retorna imediatamente.
    if (result.valid === true || result.valid === false) {
      return {
        service: 'SMTP Validation',
        found: result.valid,
        url: null,
        info: result.info + ` (via ${mx.exchange})`,
        reason: result.reason
      };
    }
  }

  return {
    service: 'SMTP Validation',
    found: null,
    url: null,
    info: 'Não foi possível validar (Possível bloqueio da porta 25 pelo seu provedor ou Greylisting do MX)',
    reason: 'INCONCLUSIVE_ALL_MX'
  };
}
