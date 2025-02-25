# === Stage 1: Node.js を使って Prisma Client を生成する ===
FROM node:18 AS builder
WORKDIR /app

# package.json と package-lock.json をコピーして依存関係をインストール
COPY package.json package-lock.json* ./
RUN npm install

# プロジェクトの全ファイルをコピー
COPY . .

# Prisma Client の生成
RUN npx prisma generate

# === Stage 2: Bun のイメージを使って最終イメージを構築する ===
FROM oven/bun:latest
WORKDIR /nowex35-auth

# Builder ステージから必要なファイルをコピーする
COPY --from=builder /app/package.json ./
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/@prisma/client ./node_modules/@prisma/client
COPY --from=builder /app ./

# Bun による依存関係のインストール
RUN bun install

# 必要なポートを公開
EXPOSE 3000

# アプリケーション起動
CMD ["sh", "-c", "bun prisma migrate deploy && bun run src/server.ts"]