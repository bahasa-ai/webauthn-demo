import { compareSync } from 'bcrypt'
import { Request, Response } from 'express'
import { sign } from 'jsonwebtoken'
import users from './users.json'

export default async function (req: Request, res: Response) {
  const { username, password } = req.body
  const user = users.find(user => user.username === username)
  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password' })
  }

  const isPasswordValid = compareSync(password, user.password)
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid username or password' })
  }

  if (user?.securityKeys?.length) {
    const token = sign({ user }, process.env.SECRET || 'secret-key', { expiresIn: '1m' })
    return res.status(403).json({ message: 'Security key required', temp_token: token })
  }

  const token = sign({ user }, process.env.SECRET || 'secret-key', { expiresIn: '1h' })
  return res.send({ access_token: token, user })
}