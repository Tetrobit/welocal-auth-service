FROM node:18-alpine

WORKDIR /app

COPY package.json .

RUN npm install

COPY . .
COPY .env.prod .env

EXPOSE 10409

RUN npm run build

CMD ["npm", "start"]