/**
 * OSINT Hunter v2.0 — Professional Logger
 * Sistema de logging estruturado com níveis, timestamps e output para arquivo
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import chalk from 'chalk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LOGS_DIR = path.join(__dirname, '..', 'logs');

if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}

const LEVELS = {
  DEBUG: { value: 0, label: 'DEBUG', color: chalk.gray },
  INFO:  { value: 1, label: 'INFO ', color: chalk.cyan },
  WARN:  { value: 2, label: 'WARN ', color: chalk.yellow },
  ERROR: { value: 3, label: 'ERROR', color: chalk.red },
  FATAL: { value: 4, label: 'FATAL', color: chalk.bgRed.white },
};

class Logger {
  constructor(options = {}) {
    this.level = LEVELS[options.level?.toUpperCase()] || LEVELS.INFO;
    this.verbose = options.verbose || false;
    this.toFile = options.toFile !== false;
    this.module = options.module || 'CORE';

    if (this.toFile) {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
      this.logFile = path.join(LOGS_DIR, `osint_${timestamp}.log`);
    }
  }

  _format(level, module, message, data = null) {
    const ts = new Date().toISOString();
    const base = `[${ts}] [${level.label}] [${module}] ${message}`;
    if (data) {
      return `${base} | ${JSON.stringify(data)}`;
    }
    return base;
  }

  _write(level, message, data = null) {
    if (level.value < this.level.value) return;

    const mod = this.module;
    const raw = this._format(level, mod, message, data);

    // Console output (com cores)
    if (this.verbose || level.value >= LEVELS.INFO.value) {
      const prefix = level.color(`[${level.label}]`);
      const modTag = chalk.gray(`[${mod}]`);
      const ts = chalk.gray(`[${new Date().toLocaleTimeString('pt-BR')}]`);
      const msg = level.value >= LEVELS.WARN.value ? level.color(message) : message;
      console.error(`  ${ts} ${prefix} ${modTag} ${msg}`);
    }

    // File output
    if (this.toFile && this.logFile) {
      try {
        fs.appendFileSync(this.logFile, raw + '\n');
      } catch { /* ignore write errors */ }
    }
  }

  debug(msg, data) { this._write(LEVELS.DEBUG, msg, data); }
  info(msg, data)  { this._write(LEVELS.INFO, msg, data); }
  warn(msg, data)  { this._write(LEVELS.WARN, msg, data); }
  error(msg, data) { this._write(LEVELS.ERROR, msg, data); }
  fatal(msg, data) { this._write(LEVELS.FATAL, msg, data); }

  /**
   * Cria um sub-logger para um módulo específico
   */
  child(module) {
    const child = new Logger({
      level: Object.keys(LEVELS).find(k => LEVELS[k] === this.level),
      verbose: this.verbose,
      toFile: this.toFile,
      module,
    });
    child.logFile = this.logFile;
    return child;
  }
}

// Instância global singleton
let _instance = null;

export function initLogger(options = {}) {
  _instance = new Logger(options);
  return _instance;
}

export function getLogger(module = 'CORE') {
  if (!_instance) {
    _instance = new Logger({ module });
  }
  return module !== 'CORE' ? _instance.child(module) : _instance;
}

export default Logger;
