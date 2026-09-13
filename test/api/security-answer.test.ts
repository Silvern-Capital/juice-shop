/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import { setTimeout as sleep } from 'node:timers/promises'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/SecurityAnswers', () => {
  void it('GET all security answers is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST new security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(authHeader)
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST security answer cannot be planted on an account without one to reset its password', async () => {
    const email = `testing@${config.get<string>('application.domain')}`

    for (let UserId = 1; UserId <= 25; UserId++) {
      const res = await request(app)
        .post('/api/SecurityAnswers')
        .set(jsonHeader)
        .send({ UserId, SecurityQuestionId: 1, answer: 'Horst' })

      assert.equal(res.status, 401)
    }

    const questionRes = await request(app).get(`/rest/user/security-question?email=${encodeURIComponent(email)}`)
    assert.deepEqual(questionRes.body, {})

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({ email, answer: 'Horst', new: 'pwn3d-by-anyone', repeat: 'pwn3d-by-anyone' })

    assert.equal(resetRes.status, 401)

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email, password: 'IamUsedForTesting' })

    assert.equal(loginRes.status, 200)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('PUT update existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .put('/api/SecurityAnswers/1')
      .set(authHeader)
      .send({
        answer: 'Blurp'
      })

    assert.equal(res.status, 401)
  })

  void it('DELETE existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .delete('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })
})

void describe('/api/Users', () => {
  void it('POST new user with security question and answer stores the answer for exactly that user', async () => {
    const email = 'new.user@te.st'

    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email,
        password: '12345',
        securityQuestion: { id: 1 },
        securityAnswer: 'Horst'
      })

    assert.equal(userRes.status, 201)
    await sleep(500)

    const questionRes = await request(app).get(`/rest/user/security-question?email=${encodeURIComponent(email)}`)
    assert.equal(questionRes.body.question?.id, 1)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({ email, answer: 'Horst', new: 'ncc-1701', repeat: 'ncc-1701' })

    assert.equal(resetRes.status, 200)
  })

  void it('POST new user without security question and answer leaves the account without one', async () => {
    const email = 'no.answer@te.st'

    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password: '12345' })

    assert.equal(userRes.status, 201)
    await sleep(500)

    const questionRes = await request(app).get(`/rest/user/security-question?email=${encodeURIComponent(email)}`)
    assert.deepEqual(questionRes.body, {})
  })
})
