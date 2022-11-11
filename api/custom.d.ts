export interface IUser {
  id: number,
  username: string,
  password: string,
  challenge: string | null,
  securityKeys?: {
    id: string,
    details: Record<string, any>
  }[]
}