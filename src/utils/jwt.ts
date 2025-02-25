import {sign, verify} from 'jsonwebtoken'

export const createAccessToken = (userId: string, JWT_SECRET: string) => {
    return sign({userId}, JWT_SECRET, {expiresIn: '15m'})
}

export const createRefreshToken = (userId: string, JWT_SECRET: string) => {
    return sign({userId}, JWT_SECRET, {expiresIn: '7d'})
}

export const verifyToken = (token: string, JWT_SECRET: string) => {
    return verify(token, JWT_SECRET) as {userId: string}
}