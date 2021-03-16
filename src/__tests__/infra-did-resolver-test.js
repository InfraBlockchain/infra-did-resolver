import { Resolver } from 'did-resolver'
import { getResolver } from "../infra-did-resolver.js"
import { Numeric } from "eosjs";
import { Buffer } from "buffer";

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
        // rpcEndpoint: 'http://localhost:8888'
        rpcEndpoint: 'http://9aa68844df1f.ngrok.io'
      },
      {
        networkId: 'vapptest1',
        registryContract: 'fmapkumrotfc',
        rpcEndpoint: 'https://api.testnet.eos.io'
      }
    ]
  }

  let infraDidResolver, didResolver

  beforeAll(async () => {

    infraDidResolver = getResolver(config)
    didResolver = new Resolver({ ...infraDidResolver })
  })

  describe('Public-Key-based DID', () => {
    it('resolves DID document', async () => {
      const networkId = 'vapptest1'
      // const pubKey = 'PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx'
      const pubKey = 'PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc'

      const did = `did:infra:${networkId}:${pubKey}`
      const didDoc = await didResolver.resolve(did)

      const pubKeyHex = Buffer.from(Numeric.stringToPublicKey(pubKey).data).toString('hex')
      // const pubKeyBase58 = Numeric.binaryToBase58(Numeric.stringToPublicKey(pubKey).data)

      // console.log({didDoc})
      console.dir(didDoc, { depth: null })
      expect(didDoc).toEqual({
        '@context': 'https://w3id.org/did/v1',
        id: did,
        publicKey: [
          {
            id: `${did}#controller`,
            type: 'Secp256k1VerificationKey2018',
            controller: did,
            // publicKeyBase58: pubKeyBase58
            publicKeyHex: pubKeyHex
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

  describe('Account-based DID', () => {
    it('resolves DID document', async () => {
      const networkId = 'vapptest1'

      const did = `did:infra:${networkId}:fmapkumrotfc`
      const didDoc = await didResolver.resolve(did)

      // console.log({didDoc})
      console.dir(didDoc, {depth: null})
      console.log(JSON.stringify(didDoc))

    })
  })
})
