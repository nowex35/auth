import type { MiddlewareHandler } from 'hono'
import { verify } from 'jsonwebtoken'

export const authMiddleware: MiddlewareHandler = async (c, next) => {
    const JWT_SECRET = c.env.JWT_SECRET as string
    if ( !JWT_SECRET ) {
        throw new Error('JWT_SECRET is not defined in the environment')
    }
    const token = c.req.header('Authorization')?.split(' ')[1]
    if ( !token ) return c.json({error: 'Unauthorized'}, 401)

    try {
        const decoded = verify(token, JWT_SECRET) as { userId: string } | undefined
        c.set('user', decoded)
        await next()
    } catch {
        return c.json({error : 'Invalid token'}, 401)
    }
}