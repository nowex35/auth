import { Hono } from 'hono'
import { cors } from 'hono/cors'
import  auth  from './routes/auth'

type Bindings = {
    DATABASE_URL: string
    JWT_SECRET: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('*', cors({ origin: '*' }))

app.route('/auth', auth)

export default {
    port : 3000,
    fetch: app.fetch
}
