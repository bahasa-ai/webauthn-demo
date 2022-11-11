import { generateRegistrationOptions } from '@simplewebauthn/server'
import { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/typescript-types'
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

  let options: PublicKeyCredentialCreationOptionsJSON
  try {
    options = generateRegistrationOptions({
      rpName: 'WebAuthn Demo',
      rpID: 'localhost',
      userID: user.id.toString(),
      userName: user.username,
      excludeCredentials: user.securityKeys?.map(authenticator => ({
        id: authenticator.details.credentialID,
        type: 'public-key'
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required'
      }
    })
  } catch (error) {
    console.error(error)
    return res.status(500).send(error)
  }

  writeFileSync(`${__dirname}/../users.json`, JSON.stringify(
    users.map((u: IUser) => {
      if (u.id === user.id) {
        return {
          ...u,
          challenge: options.challenge
        }
      }
      return u
    }), null, 2
  ), 'utf-8')

  return res.send(options)
}