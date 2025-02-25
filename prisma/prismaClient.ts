import { PrismaClient } from '@prisma/client'

const globalForPrisma = global as unknown as { prisma?: PrismaClient }

export function getPrisma(env: { DATABASE_URL: string }) {
    if (!globalForPrisma.prisma) {
        globalForPrisma.prisma = new PrismaClient({
            datasourceUrl: env.DATABASE_URL,
        })
    }
    return globalForPrisma.prisma
}

// 環境変数から JWT_SECRET を取得する関数
export function getJWTSecret(env?: { JWT_SECRET?: string }) {
    const secret = env?.JWT_SECRET ?? process.env.JWT_SECRET;

    if (!secret) {
        throw new Error("❌ JWT_SECRET is not set in environment variables!");
    }

    return secret;
}
