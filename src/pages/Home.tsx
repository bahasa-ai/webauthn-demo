import { Button, Col, Container, Grid, Group, Input, Paper, PasswordInput, ScrollArea, Stack, Text, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useLocalStorage } from '@mantine/hooks'
import { showNotification } from '@mantine/notifications'
import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import { AuthenticationCredentialJSON, RegistrationCredentialJSON } from '@simplewebauthn/typescript-types'
import axios from 'axios'
import { useEffect, useState } from 'react'

interface Login {
  username: string,
  password: string
}

export default function () {
  const form = useForm<Login>()
  const [token, setToken] = useLocalStorage<{ access_token: string, user: any } | null>({
    key: 'token', defaultValue: null })
  const [authenticated, setAuthenticated] = useState<boolean | null>(null)
  const [registeredDevices, setRegisteredDevices] = useState<any[]>()
  const [authenticatedDevices, setAuthenticatedDevices] = useState<any[]>()

  useEffect(() => {
    (async () => {
      try {
        const { data } = await axios.get('/api/check', {
          headers: { authorization: `Bearer ${token?.access_token}` }
        })
        setAuthenticated(data.ok)
      } catch (error) {
        setAuthenticated(false)
      }
    })()
  }, [token])

  const login = async (data: Login) => {
    try {
      const { data: resp } = await axios.post('/api/login', data)
      setToken(resp)
      window.location.reload()
    } catch (error: any) {
      if (error?.response.status === 403) {
        return auth(error?.response.data?.temp_token)
      }
      form.setFieldError('password', error.response?.data?.message)
    }
  }

  const logout = async () => {
    setToken(null)
    window.location.reload()
  }

  const register = async () => {
    const { data: options } = await axios.post('/api/webauthn/register', {}, {
      headers: { Authorization: `Bearer ${token?.access_token}` }
    })
    const resp: RegistrationCredentialJSON = await startRegistration(options)

    try {
      const { data } = await axios.post('/api/webauthn/verifyRegister', resp, {
        headers: { Authorization: `Bearer ${token?.access_token}` }
      })
      setRegisteredDevices([...registeredDevices || [], data])
      return showNotification({
        title: 'Success',
        message: 'Registration successful',
        color: 'green'
      })
    } catch (error) {
      return showNotification({
        title: 'Error',
        message: 'Registration failed',
        color: 'red'
      })
    }
  }

  const auth = async (tempToken: string) => {
    const { data: options } = await axios.post('/api/webauthn/auth', { temp_token: tempToken }, {
      headers: { Authorization: `Bearer ${token?.access_token}` }
    })
    const resp: AuthenticationCredentialJSON = await startAuthentication(options)

    try {
      const { data } = await axios.post('/api/webauthn/verifyAuth', {
        ...resp, temp_token: tempToken }, {
        headers: { Authorization: `Bearer ${token?.access_token}` }
      })
      const { verification: device, ...tokenData } = data
      setToken(tokenData)
      setAuthenticatedDevices([...authenticatedDevices || [], device])
      return showNotification({
        title: 'Success',
        message: 'Authentication successful',
        color: 'green',
        onClose: () => setAuthenticated(true)
      })
    } catch (error) {
      return showNotification({
        title: 'Error',
        message: 'Authentication failed',
        color: 'red'
      })
    }
  }

  return <Container mt="xl">
    {authenticated === true && <>
      <Title mb="lg">Authenticated</Title>
      <Group>
        <Button color="red" onClick={logout}>Logout</Button>
        <Button onClick={register}>
          Register WebAuthn
        </Button>
      </Group>
      <Stack>
        {registeredDevices?.length && <Title mt="xl" order={5}>Registered Devices</Title>}
        {registeredDevices?.map((device, i) => <Paper key={i}>
          <ScrollArea>
            <Text component="pre">
              {JSON.stringify(device, null, 2)}
            </Text>
          </ScrollArea>
        </Paper>)}
      </Stack>
      <Stack>
        {authenticatedDevices?.length && <Title mt="xl" order={5}>Authenticated Devices</Title>}
        {authenticatedDevices?.map((device, i) => <Paper key={i}>
          <ScrollArea>
            <Text component="pre">
              {JSON.stringify(device, null, 2)}
            </Text>
          </ScrollArea>
        </Paper>)}
      </Stack>
    </>}

    {authenticated === false && <>
      <Title mb="lg">Login</Title>
      <Grid>
        <Col span={6}>
          <form onSubmit={form.onSubmit((data) => login(data))}>
            <Input.Wrapper>
              <Input placeholder="username" {...form.getInputProps('username')} />
            </Input.Wrapper>
            <Input.Wrapper mt="md">
              <PasswordInput placeholder="password" {...form.getInputProps('password')} />
            </Input.Wrapper>
            <Group mt="lg" position="right">
              <Button type="submit">
                Submit
              </Button>
            </Group>
          </form>
        </Col>
      </Grid>
    </>}
  </Container>
}