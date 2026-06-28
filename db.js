require('dotenv').config();
const { Pool } = require('pg');

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
    };

const pool = new Pool(poolConfig);

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};