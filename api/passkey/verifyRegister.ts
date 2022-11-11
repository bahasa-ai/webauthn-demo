import { VerifiedRegistrationResponse, verifyRegistrationResponse } from '@simplewebauthn/server'
import { Request, Response } from 'express'
import { writeFileSync } from 'fs'
import { verify } from 'jsonwebtoken'
import { IUser } from '../custom'
import users from '../users.json'

export default async function (req: Request, res: Response) {
  const { authorization } = req.headers
  const token = authorization?.split(' ')[1]
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

  let verification: VerifiedRegistrationResponse
  try {
    verification = await verifyRegistrationResponse({
      credential: req.body,
      expectedChallenge: updatedUser.challenge,
      expectedOrigin: [
        'http://localhost:3001',
      ],
      expectedRPID: 'localhost',
      requireUserVerification: true
    })
  } catch (error: any) {
    console.error(error)
    return res.status(500).send({ error: error.message, details: error })
  }

  if (verification.verified && verification.registrationInfo) {
    writeFileSync(`${__dirname}/../users.json`, JSON.stringify(
      users.map((u: IUser) => {
        if (u.id === user.id) {
          return {
            ...user,
            challenge: null,
            securityKeys: [
              ...user.securityKeys || [],
              {
                id: Buffer.from(verification.registrationInfo?.credentialID || '').toString('base64url'),
                details: {
                  credentialPublicKey: verification.registrationInfo?.credentialPublicKey,
                  credentialID: verification.registrationInfo?.credentialID,
                  counter: verification.registrationInfo?.counter
                }
              }
            ]
          }
        }
        return u
      }), null, 2
    ), 'utf-8')
    return res.send(verification)
  }
  return res.status(401).json({ message: 'Invalid device' })
}