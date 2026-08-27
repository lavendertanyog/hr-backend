const dotenv = require('dotenv');
const { Pool, types } = require('pg');

// DATE columns (OID 1082): return the raw 'YYYY-MM-DD' string instead of node-postgres's
// default JS Date object, which is constructed in the server process's LOCAL timezone and
// then serialized to UTC by res.json() — shifting the calendar date back a day whenever the
// server's local timezone is ahead of UTC (e.g. Asia/Singapore, Asia/Kuala_Lumpur).
types.setTypeParser(1082, (val) => val);

const isRenderEnvironment = Boolean(process.env.RENDER) || Boolean(process.env.RENDER_SERVICE_NAME);
if (!isRenderEnvironment) {
  dotenv.config();
}

const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const databaseUrl = process.env.DATABASE_URL || '';
const isLocalDatabaseUrl = /localhost|127\.0\.0\.1/i.test(databaseUrl);

const poolConfig = hasDatabaseUrl
  ? {
      connectionString: databaseUrl,
      ssl: process.env.DB_SSL === 'false' || isLocalDatabaseUrl ? false : { rejectUnauthorized: false },
    }
  : {
      user: process.env.DB_USER,
      host: process.env.DB_HOST,
      database: process.env.DB_DATABASE,
      password: process.env.DB_PASSWORD,
      port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
      ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false },
    };

const pool = new Pool(poolConfig);

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};