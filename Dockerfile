FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev \
    && node -e "const oidc=require('express-openid-connect'); if (typeof oidc.auth !== 'function') { console.error('express-openid-connect.auth is unavailable'); process.exit(1); } console.log('OIDC CommonJS export check passed');"
COPY . .
ENV NODE_ENV=production
EXPOSE 3000
USER node
CMD ["npm","start"]
