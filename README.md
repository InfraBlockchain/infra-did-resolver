# infra-did-resolver

DIF Javascript DID universal resolver (https://github.com/decentralized-identity/did-resolver) compatible Infra DID resolver

- Infra DID Method Spec

  - https://github.com/InfraBlockchain/infra-did-method-specs/blob/main/docs/Infra-DID-method-spec.md

- Infra DID Registry Smart Contract on InfraBlockchain

  - https://github.com/InfraBlockchain/infra-did-registry

- Infra DID javascript library

  - https://github.com/InfraBlockchain/infra-did-js

- Infra SS58-DID Substrate Node

  - https://github.com/InfraBlockchain/infra-did-substrate

## Infra DID resolver setup with DIF did-resolver

```javascript
import { DIDResolutionResult, Resolver } from 'did-resolver'
import { getResolver } from 'infra-did-resolver'

const config: ConfigurationOptions = {
  networks: [
    {
      networkId: 'test01',
      registryContract: 'infradidregi',
      rpcEndpoint: 'https://api.testnet.infrablockchain.com',
    },
    {
      networkId: 'sentinel',
      registryContract: 'infradidregi',
      rpcEndpoint: 'https://api.sentinel.infrablockchain.com',
    },
  ],
}

const infraDidResolver = getResolver(config)
const didResolver = new Resolver({ ...infraDidResolver })
```

## DID _resolve_ operation

### `Pub-Key DID`

```javascript
const did = `did:infra:sentinel:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx`
const didResolveRes: DIDResolutionResult = await didResolver.resolve(did)
console.log({ didResolveRes })
```

- example DID resolve result

```json
{
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json"
  },
  "didDocument": {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "did:infra:sentinel:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx",
    "verificationMethod": [
      {
        "id": "did:infra:sentinel:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx#controller",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": "did:infra:sentinel:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx",
        "publicKeyHex": "037e84547231650e816a32eb5b79028e71ac7459bbcd8e81e6697ac9022e64a407"
      }
    ],
    "authentication": ["did:infra:sentinel:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx#controller"],
    "service": [
      {
        "id": "did:infra:sentinel:PUB_K1_7nxEa8qHEiy34dpuYH4yE2zRWaAoeT1gsdTnh8n5ikapZZrzjx#service-1",
        "type": "MessagingService",
        "serviceEndpoint": "https://infradid.com/pk/3/mysvcr4"
      }
    ]
  },
  "didDocumentMetadata": {}
}
```

### `Account DID`

```javascript
const did = `did:infra:sentinel:fmapkumrotfc`
const didResolveRes: DIDResolutionResult = await didResolver.resolve(did)
console.log({ didResolveRes })
```

- example DID resolve result

```json
{
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json"
  },
  "didDocument": {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "did:infra:sentinel:fmapkumrotfc",
    "verificationMethod": [
      {
        "id": "did:infra:sentinel:fmapkumrotfc#controller",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": "did:infra:sentinel:fmapkumrotfc",
        "publicKeyHex": "02eb633bb3dea58ca00330a2be557050e8889e69b8913c6f10966304c4aff91628"
      }
    ],
    "authentication": ["did:infra:sentinel:fmapkumrotfc#controller"]
  },
  "didDocumentMetadata": {}
}
```

## Infra SS58 DID resolver setup

```javascript
import InfraSS58DIDResolver from '../infra-ss58-did-resolver'
const address = 'ws://localhost:9944'

const resolver = await InfraSS58DIDResolver.createAsync(address)
```

## Infra SS58 DID _resolve_ operation

```javascript
const did = 'did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2'
const didDocument = await resolver.resolve(did)
console.log({ didDocument })
```

- example DID resolve result

```json
{
  "didDocument": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2",
    "controller": ["did:infra:025FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2"],
    "publicKey": [
      {
        "id": "did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2#keys-1",
        "type": "Ed25519VerificationKey2018",
        "controller": "did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2",
        "publicKeyBase58": "8GRSQ6nb23zkWqV8jmxYgA3e3vmxAsnvFKYCVcLb89Hw"
      }
    ],
    "authentication": ["did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2#keys-1"],
    "assertionMethod": ["did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2#keys-1"],
    "keyAgreement": [],
    "capabilityInvocation": ["did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2#keys-1"],
    "ATTESTS_IRI": null,
    "service": []
  }
}
```
