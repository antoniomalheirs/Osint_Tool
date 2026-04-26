/**
 * OSINT Hunter v2.0 — Database Module
 * Gerencia o banco de dados SQLite local para histórico de investigações
 */

import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { getConfig } from './config.js';
import { getLogger } from './logger.js';

const log = getLogger('DATABASE');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_DIR = path.join(__dirname, '..', 'db');

let _db = null;

/**
 * Inicializa a conexão e estrutura o banco (se não existir)
 */
export function initDB() {
  const config = getConfig();
  if (!config.database.enabled) return null;

  if (!fs.existsSync(DB_DIR)) {
    fs.mkdirSync(DB_DIR, { recursive: true });
  }

  const dbPath = path.join(DB_DIR, config.database.filename || 'osint_history.db');
  
  try {
    _db = new Database(dbPath, { fileMustExist: false });
    
    // Tabela de Investigações
    _db.exec(`
      CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        target_type TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        presence_score INTEGER,
        risk_level TEXT,
        profile_type TEXT
      )
    `);

    // Tabela de Resultados por Plataforma (Username)
    _db.exec(`
      CREATE TABLE IF NOT EXISTS results_username (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER,
        site TEXT NOT NULL,
        url TEXT NOT NULL,
        confidence TEXT,
        FOREIGN KEY (investigation_id) REFERENCES investigations (id) ON DELETE CASCADE
      )
    `);

    // Tabela de Inteligência Inferida
    _db.exec(`
      CREATE TABLE IF NOT EXISTS intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id INTEGER,
        data_type TEXT NOT NULL,
        data_value TEXT NOT NULL,
        FOREIGN KEY (investigation_id) REFERENCES investigations (id) ON DELETE CASCADE
      )
    `);

    log.info(`Banco de dados inicializado com sucesso em ${dbPath}`);
    return _db;
  } catch (error) {
    log.error(`Erro ao inicializar SQLite: ${error.message}`);
    return null;
  }
}

/**
 * Salva os resultados de uma investigação completa no banco
 */
export function saveInvestigation(target, isEmail, usernameResults, emailResults, correlatorIntel) {
  if (!_db) return;

  try {
    const insertInv = _db.prepare(`
      INSERT INTO investigations (target, target_type, presence_score, risk_level, profile_type)
      VALUES (?, ?, ?, ?, ?)
    `);

    const type = isEmail ? 'EMAIL' : 'USERNAME';
    const info = insertInv.run(
      target, 
      type, 
      correlatorIntel?.presenceScore || 0,
      correlatorIntel?.riskLevel || 'UNKNOWN',
      correlatorIntel?.profileType || 'UNKNOWN'
    );
    const invId = info.lastInsertRowid;

    // Salva resultados de plataforma encontrados
    const insertRes = _db.prepare(`
      INSERT INTO results_username (investigation_id, site, url, confidence)
      VALUES (?, ?, ?, ?)
    `);

    if (usernameResults) {
      const transaction = _db.transaction((results) => {
        for (const r of results) {
          if (r.found && !r.error && !r.skipped) {
            insertRes.run(invId, r.site, r.url, r.confidence);
          }
        }
      });
      transaction(usernameResults);
    }

    // Salva inteligência inferida
    const insertIntel = _db.prepare(`
      INSERT INTO intel (investigation_id, data_type, data_value)
      VALUES (?, ?, ?)
    `);

    if (correlatorIntel && correlatorIntel.metadataIntel) {
      const { inferredNames, commonAvatars } = correlatorIntel.metadataIntel;
      
      const intelTransaction = _db.transaction(() => {
        inferredNames.forEach(name => insertIntel.run(invId, 'NAME', name));
        commonAvatars.forEach(url => insertIntel.run(invId, 'AVATAR', url));
        if (correlatorIntel.emailLinked) {
          insertIntel.run(invId, 'FLAG', 'EMAIL_LINKED_TO_USERNAME');
        }
      });
      intelTransaction();
    }

    log.debug(`Investigação salva no banco com sucesso (ID: ${invId})`);
  } catch (error) {
    log.error(`Falha ao salvar investigação no banco: ${error.message}`);
  }
}

/**
 * Recupera histórico recente
 */
export function getHistory(limit = 10) {
  if (!_db) return [];
  try {
    const stmt = _db.prepare(`
      SELECT * FROM investigations 
      ORDER BY timestamp DESC LIMIT ?
    `);
    return stmt.all(limit);
  } catch (error) {
    log.error(`Falha ao ler histórico: ${error.message}`);
    return [];
  }
}
