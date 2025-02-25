import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import auth from '../auth';
import { getPrisma, getJWTSecret } from '../../../prisma/prismaClient';
import { hash, compare } from 'bcryptjs';
import { verify } from 'jsonwebtoken';
import { createAccessToken, createRefreshToken } from '../../utils/jwt';
import Redis from 'ioredis';

// モックの設定
vi.mock('../../../prisma/prismaClient', () => ({
    getPrisma: vi.fn(),
    getJWTSecret: vi.fn()
}));

vi.mock('bcryptjs', () => ({
    hash: vi.fn(),
    compare: vi.fn()
}));

vi.mock('jsonwebtoken', () => ({
    verify: vi.fn()
}));

vi.mock('../../utils/jwt', () => ({
    createAccessToken: vi.fn(),
    createRefreshToken: vi.fn()
}));

vi.mock('ioredis', () => {
    return {
        default: vi.fn().mockImplementation(() => ({
            set: vi.fn(),
            get: vi.fn(),
            del: vi.fn()
        }))
    };
});

describe('認証ルートのテスト', () => {
    let app: Hono;
    let mockPrisma: any;
    let mockEnv: any;

    beforeEach(() => {
        // データベースのモック
        mockPrisma = {
            user: {
                findUnique: vi.fn(),
                create: vi.fn(),
                update: vi.fn()
            },
            refreshToken: {
                findUnique: vi.fn(),
                create: vi.fn(),
                delete: vi.fn()
            }
        };

        // 環境変数のモック
        mockEnv = {
            JWT_SECRET: 'test_secret',
            DATABASE_URL: 'mock_database_url',
            REDIS_URL: 'mock_redis_url'
        };

        (getPrisma as any).mockReturnValue(mockPrisma);
        (getJWTSecret as any).mockReturnValue('test_secret');

        // Honoアプリ作成
        app = new Hono().route('', auth);
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    describe('サインアップAPI', () => {
        it('新規ユーザーを登録できること', async () => {
            // モックの設定
            mockPrisma.user.findUnique.mockResolvedValue(null);
            mockPrisma.user.create.mockResolvedValue({
                id: '123',
                email: 'test@example.com'
            });
            (hash as any).mockResolvedValue('hashedpassword');

            // テスト用リクエスト
            const req = new Request('http://localhost/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: 'test@example.com',
                    password: 'password123'
                })
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(200);
            const data = await res.json();
            expect(data).toEqual({ id: '123', email: 'test@example.com' });

            // モックの検証
            expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
                where: { email: 'test@example.com' }
            });
            expect(hash).toHaveBeenCalledWith('password123', 10);
            expect(mockPrisma.user.create).toHaveBeenCalledWith({
                data: {
                    email: 'test@example.com',
                    password: 'hashedpassword',
                    provider: 'local'
                }
            });
        });

        it('既存のユーザーがいる場合はエラーを返すこと', async () => {
            // モックの設定
            mockPrisma.user.findUnique.mockResolvedValue({
                id: '123',
                email: 'test@example.com'
            });

            // テスト用リクエスト
            const req = new Request('http://localhost/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: 'test@example.com',
                    password: 'password123'
                })
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(400);
            const error = await res.json();
            expect(error.message).toBe('User already exists');
        });
    });

    describe('ログインAPI', () => {
        it('正しい認証情報でログインできること', async () => {
            // モックの設定
            mockPrisma.user.findUnique.mockResolvedValue({
                id: '123',
                email: 'test@example.com',
                password: 'hashedpassword',
                provider: 'local'
            });
            (compare as any).mockResolvedValue(true);
            (createAccessToken as any).mockReturnValue('access_token');
            (createRefreshToken as any).mockReturnValue('refresh_token');

            // テスト用リクエスト
            const req = new Request('http://localhost/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: 'test@example.com',
                    password: 'password123'
                })
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(200);
            const data = await res.json();
            expect(data).toEqual({ accessToken: 'access_token' });

            // クッキーの検証
            const cookies = res.headers.get('Set-Cookie');
            expect(cookies).toBeTruthy();
            expect(cookies).toContain('refreshToken=refresh_token');
        });

        it('誤った認証情報ではエラーを返すこと', async () => {
            // モックの設定
            mockPrisma.user.findUnique.mockResolvedValue({
                id: '123',
                email: 'test@example.com',
                password: 'hashedpassword',
                provider: 'local'
            });
            (compare as any).mockResolvedValue(false);

            // テスト用リクエスト
            const req = new Request('http://localhost/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: 'test@example.com',
                    password: 'wrongpassword'
                })
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(401);
            const error = await res.json();
            expect(error.message).toBe('Invalid email or password');
        });
    });

    describe('認証検証API', () => {
        it('有効なトークンで認証できること', async () => {
            // モックの設定
            (verify as any).mockReturnValue({ email: 'test@example.com' });
            mockPrisma.user.findUnique.mockResolvedValue({
                id: '123',
                email: 'test@example.com'
            });

            // テスト用リクエスト
            const req = new Request('http://localhost/verify', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer valid_token'
                }
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(200);
            const data = await res.json();
            expect(data).toEqual(expect.objectContaining({
                email: 'test@example.com'
            }));
        });

        it('トークンなしではエラーを返すこと', async () => {
            // テスト用リクエスト
            const req = new Request('http://localhost/verify', {
                method: 'GET'
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(401);
        });
    });

    describe('ログアウトAPI', () => {
        it('ログアウト時にクッキーが削除されること', async () => {
            // リフレッシュトークンのモック
            const mockRedis = new Redis() as any;
            mockRedis.del.mockResolvedValue(1);

            // テスト用リクエスト
            const req = new Request('http://localhost/logout', {
                method: 'POST',
                headers: {
                    'Cookie': 'refreshToken=test_refresh_token'
                }
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(200);
            const cookies = res.headers.get('Set-Cookie');
            expect(cookies).toBeTruthy();
            expect(cookies).toContain('refreshToken=;');
        });
    });

    describe('トークンリフレッシュAPI', () => {
        it('リフレッシュトークンがあれば新しいアクセストークンを返すこと', async () => {
            // モックの設定
            const mockToken = 'valid_refresh_token';
            (verify as any).mockReturnValue({ email: 'test@example.com' });
            (createAccessToken as any).mockReturnValue('new_access_token');

            mockPrisma.refreshToken.findUnique.mockResolvedValue({
                token: mockToken,
                userId: '123',
                expiresAt: new Date(Date.now() + 1000 * 60 * 60), // 1時間後
                user: {
                    id: '123',
                    email: 'test@example.com'
                }
            });

            // テスト用リクエスト - POSTからGETに変更
            const req = new Request('http://localhost/refresh', {
                method: 'GET',
                headers: {
                    'Cookie': `refreshToken=${mockToken}`
                }
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(200);
            const data = await res.json();
            expect(data).toEqual({ accessToken: 'new_access_token' });
        });

        it('リフレッシュトークンがなければエラーを返すこと', async () => {
            // テスト用リクエスト - GET（クッキーなし）
            const req = new Request('http://localhost/refresh', {
                method: 'GET'
            });

            // リクエスト実行
            const res = await app.fetch(req, mockEnv);

            // レスポンスの検証
            expect(res.status).toBe(401);
        });
    });
});
