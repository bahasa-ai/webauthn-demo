import { Request, Response } from 'express'
import { verify } from 'jsonwebtoken'

export default async function (req: Request, res: Response) {
  const { authorization } = req.headers
  const token = authorization?.split(' ')[1]
  if (!token) {
    return res.status(401).json({ message: 'Invalid access token' })
  }

  try {
    const verification = verify(token, process.env.SECRET || 'secret-key') as any
    if (verification) {
      return res.send({ ok: true, user: verification.user })
    }
  } catch (error) {
    // console.error(error)
  }
  return res.status(401).json({ message: 'Invalid access token' })
}