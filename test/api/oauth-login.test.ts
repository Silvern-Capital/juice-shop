/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const jsonHeader = { 'content-type': 'application/json' }
const clientId = config.get<string>('application.googleOauth.clientId')

const originalFetch = globalThis.fetch
let tokenInfoResponse: { status: number, body: unknown }

beforeEach(() => {
  tokenInfoResponse = {
    status: 200,
    body: { aud: clientId, email: 'new.google.user@gmail.com', email_verified: true, expires_in: 3599 }
  }
  globalThis.fetch = (async (url: any) => {
    if (!String(url).includes('tokeninfo')) {
      return await originalFetch(url)
    }
    return new Response(JSON.stringify(tokenInfoResponse.body), { status: tokenInfoResponse.status, headers: jsonHeader })
  }) as typeof globalThis.fetch
})

afterEach(() => {
  globalThis.fetch = originalFetch
})

void describe('/rest/user/oauth-login', () => {
  void it('POST without access token is rejected', async () => {
    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({})
    assert.equal(res.status, 400)
  })

  void it('POST with access token rejected by the identity provider is rejected', async () => {
    tokenInfoResponse = { status: 400, body: { error: 'invalid_token' } }

    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'invalid' })
    assert.equal(res.status, 401)
  })

  void it('POST with access token issued for another OAuth client is rejected', async () => {
    tokenInfoResponse.body = { aud: 'some-other-app.apps.googleusercontent.com', email: 'evil@gmail.com', email_verified: true, expires_in: 3599 }

    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'foreign' })
    assert.equal(res.status, 401)
  })

  void it('POST with access token for an unverified email is rejected', async () => {
    tokenInfoResponse.body = { aud: clientId, email: 'unverified@gmail.com', email_verified: false, expires_in: 3599 }

    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'unverified' })
    assert.equal(res.status, 401)
  })

  void it('POST with expired access token is rejected', async () => {
    tokenInfoResponse.body = { aud: clientId, email: 'expired@gmail.com', email_verified: true, expires_in: 0 }

    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'expired' })
    assert.equal(res.status, 401)
  })

  void it('POST for an email belonging to a regular account is rejected', async () => {
    tokenInfoResponse.body = { aud: clientId, email: `admin@${config.get<string>('application.domain')}`, email_verified: true, expires_in: 3599 }

    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'valid' })
    assert.equal(res.status, 401)
  })

  void it('POST creates an account without usable password on first login', async () => {
    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'valid' })

    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
    assert.equal(res.body.authentication.umail, 'new.google.user@gmail.com')

    const user = await UserModel.findOne({ where: { email: 'new.google.user@gmail.com' } })
    assert.equal(user?.isFederated, true)

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({
        email: 'new.google.user@gmail.com',
        password: Buffer.from('new.google.user@gmail.com'.split('').reverse().join('')).toString('base64')
      })
    assert.equal(loginRes.status, 401)
  })

  void it('POST logs into the existing account on subsequent logins', async () => {
    const firstRes = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'valid' })
    const secondRes = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'valid' })

    assert.equal(firstRes.status, 200)
    assert.equal(secondRes.status, 200)
    assert.equal(firstRes.body.authentication.bid, secondRes.body.authentication.bid)
  })

  void it('POST logs into the seeded account of the Google user', async () => {
    tokenInfoResponse.body = { aud: clientId, email: 'bjoern.kimminich@gmail.com', email_verified: true, expires_in: 3599 }

    const res = await request(app).post('/rest/user/oauth-login').set(jsonHeader).send({ access_token: 'valid' })

    assert.equal(res.status, 200)
    assert.equal(res.body.authentication.umail, 'bjoern.kimminich@gmail.com')
  })
})
