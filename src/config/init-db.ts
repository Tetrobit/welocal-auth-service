import { Client } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

async function createDatabase() {
    const client = new Client({
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT || "5432"),
        user: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        database: 'postgres' // Connect to default postgres database
    });

    try {
        await client.connect();
        const dbName = process.env.DB_DATABASE;
        
        // Check if database exists
        const result = await client.query(
            "SELECT 1 FROM pg_database WHERE datname = $1",
            [dbName]
        );

        if (result.rowCount === 0) {
            // Create database if it doesn't exist
            await client.query(`CREATE DATABASE "${dbName}"`);
            console.log(`Database ${dbName} created successfully`);
        } else {
            console.log(`Database ${dbName} already exists`);
        }
    } catch (error) {
        console.error('Error creating database:', error);
        throw error;
    } finally {
        await client.end();
    }
}

export default createDatabase; 