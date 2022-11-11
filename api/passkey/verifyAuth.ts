import { VerifiedAuthenticationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server'
import { Request, Response } from 'express'
import { writeFileSync } from 'fs'
import { sign } from 'jsonwebtoken'
import { IUser } from '../custom'
import users from '../users.json'
import attempts from '../attempts.json'

export default async function (req: Request, res: Response) {
  const { attempt_id: id, ...credential } = req.body

  const updatedUser = users.find(u => (u.securityKeys || []).find((authenticator: any) => authenticator.id === req.body.id))
  if (!updatedUser) {
    return res.status(401).json({ message: 'Invalid user' })
  }

  const authenticator: any = (updatedUser.securityKeys || []).find((authenticator: any) => authenticator.id === req.body.id)
  if (!authenticator) {
    return res.status(401).json({ message: 'Invalid authenticator' })
  }

  let verification: VerifiedAuthenticationResponse
  try {
    verification = await verifyAuthenticationResponse({
      credential,
      expectedChallenge: (attempts as any[] || []).find((a: any) => a.id === id)?.challenge,
      expectedOrigin: [
        'http://localhost:3001',
      ],
      expectedRPID: 'localhost',
      authenticator: {
        credentialPublicKey: Buffer.from(authenticator?.details.credentialPublicKey as any),
        credentialID: Buffer.from(authenticator?.details.credentialID as any),
        counter: authenticator?.details.counter
      },
      requireUserVerification: true
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