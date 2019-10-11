import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'
import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')


const cert = `
-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJVoybJZhGq5dVMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi1vMnd0ZjRzNS5hdXRoMC5jb20wHhcNMTkxMDA2MjE1NTA3WhcNMzMw
NjE0MjE1NTA3WjAhMR8wHQYDVQQDExZkZXYtbzJ3dGY0czUuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAte9Fn71yO8xuWtrcyufw0A2y
GRR0mQ5wUmSzitCV/pfQ2mPnLdY76VOMau1e68LX+jXyiu2l1J845tQoShY3pz4w
qWC5a+dOd+VBlba2pfRt2zUM1dz8lNvf2ZRy7ApnSNjZmT537ZQiWbkZfYZaDmQ+
dBnSvO42YLqU2sgoZx9yHR9AXkg5qNz8jKze4wgyAo9K40WnDMMrxjUCxqeQB6/S
Q20vFEhX98kCa+nNxx3Ugsc+MyzGmahVNfBnP7uS0unhpLmBDSzGkz6/NH7dB5rr
pzJykjiZNvJRMyot/w2cdyoJ7tNKmvNNC4rqqGRiW6OlxhOSDFSDQ4Y7ou6HTQID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTr4dkFf85nOcgHA23S
PSUz3gb2ajAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAH+lzqR4
WodPO0qF0idiiUzx2SouDL53UM6jt1XG/14lRS4iM+Ngai8Ma8I4apVjC3BLT+7p
P7OsW+E5AFrLILmt7RJ381PYlzCPT6sMTZqpMIUtAVhrbpliq6vFHSdX/P9BSxed
JpRp//N3MxcchKzj7KAx3I26H7hxOEEi/sfHhD4fB0Uncfl1dJtWl80raJsgGAwm
Ag94pHppXKl7wldqixyKQNoKaaqPXnKzD94qdp9Wz2Ato8jZ0JI0Zc50whfsdQIH
VJ/72WGDGd/8DecX/kcIT4zAThNUCH2sR9rU5qik4Ah3+Wkz4NfSFI8F/80uzJXJ
aCH6FR4I/o76ryw=
-----END CERTIFICATE-----
`


export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

// receives one parameter from client to api gateway
async function verifyToken(authHeader: string): Promise<JwtPayload> {
  console.log('🌸🌸', authHeader);
  const token = getToken(authHeader)
  // const jwt: Jwt = decode(token, { complete: true }) as Jwt

  // TODO: Implement token verification ✅
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/

  // const token = need token to verify
  // const secret = used to sign this token
  // if thrown error, else valid token
  return verify(
    token,           // Token from an HTTP header to validate
    cert,            // A certificate copied from Auth0 website
    { algorithms: ['RS256'] } // We need to specify that we use the RS256 algorithm
  ) as JwtPayload;
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}