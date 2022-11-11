import { generateAuthenticationOptions } from '@simplewebauthn/server'
import { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/typescript-types'
import { Request, Response } from 'express'
import { writeFileSync } from 'fs'
import attempts from '../attempts.json'

export default async function (req: Request, res: Response) {
  const { attempt_id: id } = req.body
  let options: PublicKeyCredentialRequestOptionsJSON
  try {
    options = generateAuthenticationOptions({
      rpID: 'localhost',
      userVerification: 'required',
    })
  } catch (error) {
    console.error(error)
    return res.status(400).send(error)
  }

  writeFileSync(`${__dirname}/../attempts.json`, JSON.stringify([...attempts as any[] || [], {
    id,
    challenge: options.challenge
  }], null, 2), 'utf-8')

  return res.send(options)
}