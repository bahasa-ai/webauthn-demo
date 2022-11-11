import { generateAuthenticationOptions } from '@simplewebauthn/server'
import { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/typescript-types'
import { Request, Response } from 'express'
import { writeFileSync } from 'fs'
import { verify } from 'jsonwebtoken'
import { IUser } from '../custom'
import users from '../users.json'

export default async function (req: Request, res: Response) {
  const { temp_token: token } = req.body
  if (!token) {
    return res.status(401).json({ message: 'Invalid access token' })
  }

  const { user } = verify(token, process.env.SECRET || 'secret-key') as { user: IUser }
  if (!user) {
    return res.status(401).json({ message: 'Invalid access token' })
  }

  let options: PublicKeyCredentialRequestOptionsJSON
  try {
    options = generateAuthenticationOptions({
      allowCredentials: user.securityKeys?.map(authenticator => ({
        id: authenticator.details.credentialID,
        type: 'public-key'
      })),
      userVerification: 'preferred',
    })
  } catch (error) {
    console.error(error)
    return res.status(400).send(error)
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