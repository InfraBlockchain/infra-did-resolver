import {DIDResolutionResult, Resolver} from 'did-resolver'
import { getResolver } from "../infra-did-resolver"
import { Numeric } from "eosjs"
import { Buffer } from "buffer"
import {
  ConfigurationOptions,
} from "../configuration";

describe('infra-did-resolver', () => {

  const config: ConfigurationOptions = {
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
      const pubKey = 'PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx'
      // const pubKey = 'PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc'

      const did = `did:infra:${networkId}:${pubKey}`
      const didResolveRes: DIDResolutionResult = await didResolver.resolve(did)

      const pubKeyHex = Buffer.from(Numeric.stringToPublicKey(pubKey).data).toString('hex')
      // const pubKeyBase58 = Numeric.binaryToBase58(Numeric.stringToPublicKey(pubKey).data)

      // console.log({didDoc})
      console.log(JSON.stringify(didResolveRes, null, 3))
      expect(didResolveRes.didResolutionMetadata.contentType).toEqual("application/did+ld+json")
      expect(didResolveRes.didDocumentMetadata).toEqual({})
      expect(didResolveRes.didDocument).toEqual({
        // '@context': [
        //   'https://www.w3.org/ns/did/v1',
        //   'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld'
        // ],
        '@context': 'https://www.w3.org/ns/did/v1',
        id: did,
        verificationMethod: [
          {
            id: `${did}#controller`,
            type: 'EcdsaSecp256k1VerificationKey2019',
            controller: did,
            // publicKeyBase58: pubKeyBase58
            publicKeyHex: pubKeyHex
          }
        ],
        authentication: [
          `${did}#controller`
        ],
        service: [
          {
            id: `${did}#service-1`,
            type: 'MessagingService',
            serviceEndpoint: 'https://infradid.com/pk/3/mysvcr4'
          }
        ]
      })
    })

    it('resolves revoked DID document', async () => {
      const networkId = 'vapptest1'
      const pubKey = 'PUB_K1_7pM9qiBuHWF6WqRSjPTMfVYKV5ZFRavK4PkUq4oFhqi9Z46mWc'

      const did = `did:infra:${networkId}:${pubKey}`
      const didResolveRes: DIDResolutionResult = await didResolver.resolve(did)

      const pubKeyHex = Buffer.from(Numeric.stringToPublicKey(pubKey).data).toString('hex')
      // const pubKeyBase58 = Numeric.binaryToBase58(Numeric.stringToPublicKey(pubKey).data)

      // console.log({didDoc})
      console.dir(didResolveRes, { depth: null })
      expect(didResolveRes.didDocument.verificationMethod).toBeDefined()
      expect(didResolveRes.didDocumentMetadata.deactivated).toBeTruthy()
    })
  })

  describe('Account-based DID', () => {
    it('resolves DID document', async () => {
      const networkId = 'vapptest1'

      const did = `did:infra:${networkId}:fmapkumrotfc`
      const didResolveRes: DIDResolutionResult = await didResolver.resolve(did)

      console.log(JSON.stringify(didResolveRes, null, 3))
      expect(didResolveRes.didResolutionMetadata.contentType).toEqual("application/did+ld+json")
      expect(didResolveRes.didDocumentMetadata).toEqual({})
      expect(didResolveRes.didDocument.verificationMethod).toBeDefined()
    })
  })
})
