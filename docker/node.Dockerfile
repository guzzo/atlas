FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY sdk ./sdk
COPY apps ./apps
COPY scripts ./scripts
COPY tests ./tests
COPY api ./api
RUN npm run build

FROM node:22-bookworm-slim
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY apps/globex/migrations ./apps/globex/migrations
COPY api ./api
COPY tests ./tests
COPY sdk ./sdk
COPY scripts ./scripts
USER node
CMD ["node", "dist/apps/globex/server.js"]
