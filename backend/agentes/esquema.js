"use strict";
/**
 * Tablas de los agentes. Todo es aditivo: tablas propias más dos columnas en operation_logs.
 *
 * Las keys de agente van en su propia tabla y no en `api_keys`: aquellas se emiten desde antes y
 * ninguna ruta las valida; darles poder ahora cambiaría el significado de keys ya entregadas.
 */

async function agregarColumna(qRun, sql) {
  try { await qRun(sql); } catch (e) { if (e.code !== "ER_DUP_FIELDNAME") throw e; }
}

async function crearTablas({ qRun }) {
  const FIN = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
  const NIVEL = "ENUM('ninguno','lectura','propuesta','escritura','total') NOT NULL";

  await qRun(`CREATE TABLE IF NOT EXISTS agente_keys (
    id VARCHAR(36) PRIMARY KEY,
    nombre VARCHAR(120) NOT NULL,
    hash CHAR(64) NOT NULL,
    prefijo VARCHAR(16) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    nivel_max ${NIVEL} DEFAULT 'lectura',
    expira_en DATETIME NOT NULL,
    revocada_en DATETIME NULL,
    ultimo_uso DATETIME NULL,
    creada_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_hash (hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ${FIN}`);

  await qRun(`CREATE TABLE IF NOT EXISTS agente_key_engagements (
    key_id VARCHAR(36) NOT NULL,
    engagement_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (key_id, engagement_id),
    FOREIGN KEY (key_id) REFERENCES agente_keys(id) ON DELETE CASCADE,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ${FIN}`);

  // Sin fila acá, el engagement no da acceso a ningún agente.
  await qRun(`CREATE TABLE IF NOT EXISTS agente_engagements (
    engagement_id VARCHAR(36) PRIMARY KEY,
    nivel_max ${NIVEL} DEFAULT 'ninguno',
    mostrar_sensibles TINYINT(1) NOT NULL DEFAULT 0,
    actualizado_por VARCHAR(36),
    actualizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ${FIN}`);

  // Una sola fila (id 1). Con pausado_en, ninguna key de agente hace nada.
  await qRun(`CREATE TABLE IF NOT EXISTS agente_pausa (
    id TINYINT PRIMARY KEY,
    pausado_en DATETIME NULL,
    pausado_por VARCHAR(36) NULL
  ) ${FIN}`);
  await qRun("INSERT IGNORE INTO agente_pausa (id) VALUES (1)");
  await agregarColumna(qRun, "ALTER TABLE agente_engagements ADD COLUMN pausado_en DATETIME NULL");
  await agregarColumna(qRun, "ALTER TABLE agente_engagements ADD COLUMN pausado_por VARCHAR(36) NULL");

  // Las propuestas no van en `findings`: así no aparecen en informes, exportaciones ni conteos hasta
  // que una persona las aprueba.
  await qRun(`CREATE TABLE IF NOT EXISTS agente_propuestas (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    key_id VARCHAR(36) NOT NULL,
    key_nombre VARCHAR(120) NOT NULL,
    accion ENUM('crear','actualizar') NOT NULL,
    finding_id VARCHAR(36) NULL,
    datos JSON NOT NULL,
    estado ENUM('pendiente','aprobada','rechazada') NOT NULL DEFAULT 'pendiente',
    motivo VARCHAR(1000) NULL,
    decidida_por VARCHAR(36) NULL,
    decidida_en DATETIME NULL,
    creada_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_estado (engagement_id, estado),
    INDEX idx_recientes (estado, creada_en),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ${FIN}`);

  await qRun("ALTER TABLE agente_propuestas MODIFY accion ENUM('crear','actualizar','retest','mapa') NOT NULL");
  // Lo que la persona corrigió al aprobar. `datos` sigue siendo lo que propuso el agente.
  await agregarColumna(qRun, "ALTER TABLE agente_propuestas ADD COLUMN datos_aprobados JSON NULL");
  await agregarColumna(qRun, "ALTER TABLE agente_propuestas ADD COLUMN campos_editados JSON NULL");
  // Cómo estaba el hallazgo al proponer, para saber si cambió.
  await agregarColumna(qRun, "ALTER TABLE agente_propuestas ADD COLUMN huella CHAR(64) NULL");

  await qRun(`CREATE TABLE IF NOT EXISTS agente_violaciones (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    key_id VARCHAR(36) NOT NULL,
    key_nombre VARCHAR(120) NOT NULL,
    tipo ENUM('log','hallazgo','importacion') NOT NULL,
    log_id VARCHAR(36) NULL,
    objetivo VARCHAR(500) NOT NULL,
    motivo VARCHAR(1000) NOT NULL,
    revisada_por VARCHAR(36) NULL,
    revisada_en DATETIME NULL,
    creada_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pendientes (engagement_id, revisada_en),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
  ) ${FIN}`);

  await qRun("ALTER TABLE agente_violaciones MODIFY tipo ENUM('log','hallazgo','importacion','mapa') NOT NULL");

  await qRun(`CREATE TABLE IF NOT EXISTS agente_actividad (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    key_id VARCHAR(36) NOT NULL,
    engagement_id VARCHAR(36) NULL,
    accion VARCHAR(30) NOT NULL,
    codigo SMALLINT NOT NULL,
    objetivo VARCHAR(500) NULL,
    detalle VARCHAR(500) NULL,
    ref_id VARCHAR(36) NULL,
    fuera TINYINT(1) NOT NULL DEFAULT 0,
    veces INT UNSIGNED NOT NULL DEFAULT 1,
    creada_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultima_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_key (key_id, id),
    INDEX idx_ultima (ultima_en),
    FOREIGN KEY (key_id) REFERENCES agente_keys(id) ON DELETE CASCADE,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
  ) ${FIN}`);

  await qRun(`CREATE TABLE IF NOT EXISTS agente_idempotencia (
    key_id VARCHAR(36) NOT NULL,
    clave VARCHAR(100) NOT NULL,
    huella CHAR(64) NOT NULL,
    lista TINYINT(1) NOT NULL DEFAULT 0,
    codigo SMALLINT NULL,
    respuesta MEDIUMTEXT NULL,
    creada_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (key_id, clave),
    INDEX idx_creada (creada_en),
    FOREIGN KEY (key_id) REFERENCES agente_keys(id) ON DELETE CASCADE
  ) ${FIN}`);

  await agregarColumna(qRun, "ALTER TABLE operation_logs ADD COLUMN agente_key_id VARCHAR(36) NULL");
  await agregarColumna(qRun, "ALTER TABLE operation_logs ADD COLUMN fuera_de_alcance TINYINT(1) NOT NULL DEFAULT 0");
}

module.exports = { crearTablas };
