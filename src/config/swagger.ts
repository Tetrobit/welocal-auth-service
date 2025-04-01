import swaggerJsdoc from 'swagger-jsdoc';
import path from 'path';

const options: swaggerJsdoc.Options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'WeLocal Auth Service API',
            version: '1.0.0',
            description: 'API documentation for WeLocal Authentication Service',
        },
        servers: [
            {
                url: 'http://localhost:8088',
                description: 'Development server',
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
        },
        security: [{
            bearerAuth: [],
        }],
    },
    apis: [path.join(__dirname, '../server.ts')], // Path to the API docs
};

export const swaggerSpec = swaggerJsdoc(options); 