import { VerifiedAuthenticationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server'
import { Request, Response } from 'express'
import { writeFileSync } from 'fs'
import { sign, verify } from 'jsonwebtoken'
import { IUser } from '../custom'
import users from '../users.json'

export default async function (req: Request, res: Response) {
  const { temp_token: token, ...credential } = req.body
  if (!token) {
    return res.status(401).json({ message: 'Invalid access token' })
  }

  const { user } = verify(token, process.env.SECRET || 'secret-key') as { user: IUser }
  if (!user) {
    return res.status(401).json({ message: 'Invalid access token' })
  }

  const updatedUser = users.find((u: IUser) => u.id === user.id)
  if (!updatedUser?.challenge) {
    return res.status(401).json({ message: 'Invalid challenge' })
  }

  const authenticator: any = (updatedUser.securityKeys || [])?.find((authenticator: any) => authenticator.id === req.body.id)
  if (!authenticator) {
    return res.status(401).json({ message: 'Invalid authenticator' })
  }

  let verification: VerifiedAuthenticationResponse
  try {
    verification = await verifyAuthenticationResponse({
      credential,
      expectedChallenge: updatedUser.challenge,
      expectedOrigin: [
        'http://localhost:3001',
      ],
      expectedRPID: 'localhost',
      authenticator: {
        credentialPublicKey: Buffer.from(authenticator?.details.credentialPublicKey as any),
        credentialID: Buffer.from(authenticator?.details.credentialID as any),
        counter: authenticator?.details.counter
      },
    })
  } catch (error: any) {
    console.error(error)
    return res.status(500).send({ error: error.message, details: error })
  }

  if (verification.verified) {
    writeFileSync(`${__dirname}/../users.json`, JSON.stringify(
      users.map((u: IUser) => {
        if (u.id === updatedUser.id) {
          return {
            ...u,
            challenge: null,
            securityKeys: u.securityKeys?.map(authenticator => {
              if (authenticator.id === req.body.id) {
                return {
                  ...authenticator,
                  details: {
                    ...authenticator.details,
                    counter: verification.authenticationInfo.newCounter
                  }
                }
              }
              return authenticator
            })
          }
        }
        return u
      }), null, 2
    ), 'utf-8')
    const newToken = sign({ user: updatedUser }, process.env.SECRET || 'secret-key', { expiresIn: '1h' })
    return res.send({ access_token: newToken, user: updatedUser, verification })
  }
  return res.status(401).json({ message: 'Invalid credentials' })
}