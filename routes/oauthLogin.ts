/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { randomBytes } from 'node:crypto'
import config from 'config'

import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const tokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo'

interface GoogleTokenInfo {
  aud?: string
  azp?: string
  email?: string
  email_verified?: boolean | string
  expires_in?: number | string
}

/* Resolves the verified email address of the Google account the access token was issued for.
   Returns null for anything that cannot be attributed to a verified email of this application's own OAuth client. */
async function verifiedEmailForAccessToken (accessToken: string) {
  const response = await fetch(`${tokenInfoUrl}?access_token=${encodeURIComponent(accessToken)}`, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) {
    return null
  }
  const tokenInfo = await response.json() as GoogleTokenInfo
  const clientId = config.get<string>('application.googleOauth.clientId')
  if (tokenInfo.aud !== clientId && tokenInfo.azp !== clientId) {
    return null
  }
  if (tokenInfo.expires_in !== undefined && Number(tokenInfo.expires_in) <= 0) {
    return null
  }
  if (!tokenInfo.email || String(tokenInfo.email_verified) !== 'true') {
    return null
  }
  return tokenInfo.email
}

async function federatedUserFor (email: string) {
  const existingUser = await UserModel.findOne({ where: { email } })
  if (existingUser !== null) {
    /* Existing accounts with a password of their own are never handed out to the identity provider */
    return existingUser.isFederated ? existingUser : null
  }
  try {
    return await UserModel.create({
      email,
      password: randomBytes(32).toString('base64'), // never used for authentication but keeps the column unguessable
      isFederated: true
    })
  } catch {
    /* e.g. when the email address belongs to an erased account */
    return null
  }
}

export function oauthLogin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const accessToken = req.body?.access_token
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      res.status(400).send('Missing OAuth access token.')
      return
    }

    try {
      const email = await verifiedEmailForAccessToken(accessToken)
      if (email === null) {
        res.status(401).send('Could not verify OAuth access token.')
        return
      }

      const user = await federatedUserFor(email)
      if (user === null) {
        res.status(401).send('Could not verify OAuth access token.')
        return
      }

      const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.id } })
      const authenticatedUser = { data: user, bid: basket.id }
      const token = security.authorize(authenticatedUser)
      security.authenticatedUsers.put(token, authenticatedUser)
      res.json({ authentication: { token, bid: basket.id, umail: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
