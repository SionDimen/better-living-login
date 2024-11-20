const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

async function updateDatabase() {
    try {
        console.log('Connecting to database...'); // Debug log
        
        // Add new columns
        await pool.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS membership_expires_at TIMESTAMP,
            ADD COLUMN IF NOT EXISTS membership_status VARCHAR(20) DEFAULT 'active'
        `);
        
        console.log('Database updated successfully!');

        // Verify the changes
        const result = await pool.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'users'
        `);
        console.log('Current table structure:', result.rows);

    } catch (error) {
        console.error('Error updating database:', error);
    } finally {
        await pool.end();
    }
}

updateDatabase();