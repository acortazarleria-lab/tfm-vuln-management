-- ============================================================
-- db-init.sql
-- Inicialización de usuario y base de datos PostgreSQL
-- Ejecutar UNA VEZ tras crear la instancia RDS, vía SSM Run
-- Command desde la instancia DefectDojo (psql como usuario master)
-- ISO 27001: A.9.2.3 — gestión privilegios acceso
--
-- Las credenciales reales se recuperan de Secrets Manager:
--   vuln-mgmt/rds/master-credentials   (conexión inicial)
--   vuln-mgmt/defectdojo/db-credentials (password de ${DEFECTDOJO_PASSWORD})
-- Sustituir el placeholder antes de ejecutar, nunca hardcodear
-- en este archivo ni commitearlo con la contraseña real.
-- ============================================================

-- Base de datos DefectDojo
CREATE DATABASE defectdojo
  ENCODING 'UTF8'
  LC_COLLATE 'en_US.UTF-8'
  LC_CTYPE 'en_US.UTF-8';

-- Usuario DefectDojo — solo puede acceder a su propia DB
CREATE USER defectdojo WITH
  ENCRYPTED PASSWORD '${DEFECTDOJO_PASSWORD}'
  CONNECTION LIMIT 20
  VALID UNTIL 'infinity';

GRANT CONNECT ON DATABASE defectdojo TO defectdojo;
GRANT ALL PRIVILEGES ON DATABASE defectdojo TO defectdojo;

\c defectdojo
GRANT ALL ON SCHEMA public TO defectdojo;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO defectdojo;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON SEQUENCES TO defectdojo;

-- Revocar acceso público
\c postgres
REVOKE ALL ON DATABASE defectdojo FROM PUBLIC;

-- Verificación
SELECT datname, datacl FROM pg_database
  WHERE datname = 'defectdojo';
