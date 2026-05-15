# Cloakbuster — Next.js + Playwright (Chromium). Use bookworm-slim; Alpine is unsupported for bundled Chromium.
FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install
RUN npx playwright install --with-deps chromium
COPY . .
RUN npm run build
EXPOSE 3000
ENV NODE_ENV=production
CMD ["npm", "run", "start"]
