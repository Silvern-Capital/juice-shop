/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import config from 'config'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }
const adminWithoutAnswer = `testing@${config.get<string>('application.domain')}`

async function securityQuestionOf (email: string) {
  const res = await request(app).get(`/rest/user/security-question?email=${encodeURIComponent(email)}`)
  return res.body
}

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
    const admin = await UserModel.findOne({ where: { email: adminWithoutAnswer } })
    assert.ok(admin, `Expected seeded admin ${adminWithoutAnswer} to exist`)
    assert.deepEqual(await securityQuestionOf(adminWithoutAnswer), {})

    const plantRes = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({ UserId: admin.id, SecurityQuestionId: 1, answer: 'Horst' })

    assert.equal(plantRes.status, 401)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({ email: adminWithoutAnswer, answer: 'Horst', new: 'pwn3d-by-anyone', repeat: 'pwn3d-by-anyone' })

    assert.equal(resetRes.status, 401)

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: adminWithoutAnswer, password: 'IamUsedForTesting' })

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
    assert.equal((await securityQuestionOf(email)).question?.id, 1)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({ email, answer: 'Horst', new: 'ncc-1701', repeat: 'ncc-1701' })

    assert.equal(resetRes.status, 200)
  })

  void it('POST new user ignores a UserId in the body when storing the security answer', async () => {
    const email = 'hijacker@te.st'

    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email,
        password: '12345',
        UserId: (await UserModel.findOne({ where: { email: adminWithoutAnswer } }))?.id,
        securityQuestion: { id: 2 },
        securityAnswer: 'Horst'
      })

    assert.equal(userRes.status, 201)
    assert.equal((await securityQuestionOf(email)).question?.id, 2)
    assert.deepEqual(await securityQuestionOf(adminWithoutAnswer), {})
  })

  void it('POST new user without security question and answer leaves the account without one', async () => {
    const email = 'no.answer@te.st'

    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email, password: '12345' })

    assert.equal(userRes.status, 201)
    assert.deepEqual(await securityQuestionOf(email), {})
  })
})
