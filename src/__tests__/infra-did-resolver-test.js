import { Resolver } from 'did-resolver'
import { getResolver } from "../infra-did-resolver.js"

describe('infra-did-resolver', () => {

  const config = {
    networks : [
      {
        networkId: 'kr01',
        registryContract: 'infradidregi',
        rpcEndpoint: 'http://localhost:8888'
      },
      {
        networkId: 'local',
        registryContract: 'infradidregi',
        rpcEndpoint: 'http://localhost:8888'
      }
    ]
  }

  let infraDidResolver, didResolver

  beforeAll(async () => {

    infraDidResolver = getResolver(config)
    didResolver = new Resolver(infraDidResolver)
  })

  describe('Public-Key-based DID', () => {
    it('resolves document', async () => {
      const did = 'did:infra:local:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx'
      const didDoc = await didResolver.resolve(did)
      // console.log({didDoc})
      console.dir(didDoc, { depth: null })
      return expect(didDoc).toEqual({
        '@context': 'https://w3id.org/did/v1',
        id: did,
        publicKey: [
          {
            id: `${did}#controller`,
            type: 'Secp256k1VerificationKey2018',
            controller: did,
            publicKeyHex: '037e84547231650e816a32eb5b79028e71ac7459bbcd8e81e6697ac9022e64a407'
          }
        ],
        authentication: [
          {
            type: 'Secp256k1SignatureAuthentication2018',
            publicKey: `${did}#controller`
          }
        ]
      })
    })

  })
})
