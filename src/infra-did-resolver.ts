import { Buffer } from 'buffer'
import {JsonRpc, Numeric} from 'eosjs'
import {
  DIDDocument,
  DIDResolutionOptions,
  DIDResolutionResult,
  DIDResolver,
  ParsedDID,
  Resolver,
  ServiceEndpoint,
  VerificationMethod,
} from 'did-resolver'
import {
  legacyAlgoMap,
  legacyAttrTypes,
  LegacyVerificationMethod,
  verificationMethodTypes,
  INFRA_DID_NONCE_VALUE_FOR_REVOKED_PUB_KEY_DID,
  Errors,
} from './typedefs'
import {
  ConfigurationOptions,
  ConfiguredNetwork,
  ConfiguredNetworks,
  configureResolverWithNetworks
} from "./configuration";
import {Key} from "eosjs/dist/eosjs-numeric";

export function getResolver(options: ConfigurationOptions): Record<string, DIDResolver> {
  return new InfraDidResolver(options).build()
}

export class InfraDidResolver {
  private networks: ConfiguredNetworks
  private noRevocationCheck: boolean

  constructor(options: ConfigurationOptions) {
    this.networks = configureResolverWithNetworks(options)
    if (options.noRevocationCheck) {
      this.noRevocationCheck = true;
    } else {
      this.noRevocationCheck = false;
    }
  }

  async resolve(
    did: string,
    parsed: ParsedDID,
    _unused: Resolver,
    options: DIDResolutionOptions
  ): Promise<DIDResolutionResult> {

    const idSplit = parsed.id.split(':')
    if (idSplit.length !== 2) {
      return {
        didResolutionMetadata: {
          error: Errors.invalidDid,
          message: `invalid did, needs network identifier part and id part (${did})`,
        },
        didDocument: null,
        didDocumentMetadata: {},
      }
    }
    const network: ConfiguredNetwork = this.networks[idSplit[0]]
    if (!network) {
      return {
        didResolutionMetadata: {
          error: Errors.unknownNetwork,
          message: `no chain network configured for network identifier ${idSplit[0]}`,
        },
        didDocument: null,
        didDocumentMetadata: {},
      }
    }

    try {
      const idInNetwork: string = idSplit[1]
      let resolvedDidDoc : { didDocument: DIDDocument; deactivated: boolean }
      if (idInNetwork.startsWith("PUB_K1_") || idInNetwork.startsWith("PUB_R1_") || idInNetwork.startsWith("EOS")) {
        resolvedDidDoc = await this.resolvePubKeyDID(did, idInNetwork, network)
      } else {
        resolvedDidDoc = await this.resolveAccountDID(did, idInNetwork, network)
      }
      const status = resolvedDidDoc.deactivated ? { deactivated: true } : {}
      return {
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
        didDocument: resolvedDidDoc.didDocument,
        didDocumentMetadata: { ...status },
      }
    } catch (e) {
      return {
        didResolutionMetadata: {
          error: Errors.notFound,
          message: e.toString(), // This is not in spec, nut may be helpful
        },
        didDocument: null,
        didDocumentMetadata: {},
      }
    }
  }

  build(): Record<string, DIDResolver> {
    return { infra: this.resolve.bind(this) }
  }

  private async resolvePubKeyDID(
    did: string, pubKeyStr: string, network: ConfiguredNetwork
  ): Promise<{ didDocument: DIDDocument; deactivated: boolean }> {

    let pubKey: Key = Numeric.stringToPublicKey(pubKeyStr)
    if (pubKey.type != Numeric.KeyType.k1 /*&& pubKey.type != Numeric.KeyType.r1*/ ) {
      throw new Error("unsupported public key type")
    }

    const pubkey_index_256bits = Buffer.from(pubKey.data.slice(1,pubKey.data.length)).toString('hex')

    const resPubKeyDID = await this.jsonRpcFetchRows( network.jsonRpc, {
      code: network.registryContract, //DID_REGISTRY_CONTRACT,
      scope: network.registryContract, //DID_REGISTRY_CONTRACT,
      table: 'pubkeydid',
      index_position: 2,
      key_type: 'sha256',
      lower_bound: pubkey_index_256bits,
      upper_bound: pubkey_index_256bits,
      limit: 1
    })
    // console.log('resPubKeyDID = ' + JSON.stringify(resPubKeyDID, null, 3))

    let pkDidAttr: { key, value }[] = []
    let deactivated: boolean = false
    let ownerPubKey: Key = null

    if (resPubKeyDID.length > 0) {
      const pubkeyDIDrow = resPubKeyDID[0]
      pkDidAttr = pubkeyDIDrow.attr
      if (!this.noRevocationCheck && pubkeyDIDrow.nonce === INFRA_DID_NONCE_VALUE_FOR_REVOKED_PUB_KEY_DID) {
        deactivated = true
      }

      const resPubKeyDIDOwner = await this.jsonRpcFetchRows( network.jsonRpc, {
        json: true,
        code: network.registryContract, //DID_REGISTRY_CONTRACT,
        scope: network.registryContract, //DID_REGISTRY_CONTRACT,
        table: 'pkdidowner',
        index_position: 1,
        key_type: 'i64',
        lower_bound: pubkeyDIDrow.pkid,
        limit: 1
      })

      // console.log('resPubKeyDIDOwner = ' + JSON.stringify(resPubKeyDIDOwner, null, 3))
      if (resPubKeyDIDOwner.length > 0 && resPubKeyDIDOwner[0].pkid == pubkeyDIDrow.pkid) {
        ownerPubKey = Numeric.stringToPublicKey(resPubKeyDIDOwner[0].owner_pk)
      }
    }

    return this.wrapDidDocument(did, ownerPubKey? ownerPubKey : pubKey, pkDidAttr, deactivated)
  }

  private async resolveAccountDID(
    did: string, accountName: string, network: ConfiguredNetwork
  ): Promise<{ didDocument: DIDDocument; deactivated: boolean }> {
    const res = await network.jsonRpc.get_account(accountName);
    // console.log(JSON.stringify(res, null, 3))

    // let ownerKeyStr
    let activeKeyStr: string
    res.permissions.map(perm => {
      switch (perm.perm_name) {
        case 'active' : {
          const ra = perm.required_auth
          if (ra.threshold === 1 && ra.keys.length === 1 && ra.keys[0].weight === 1) {
            activeKeyStr = ra.keys[0].key
          }
          break
        }
        // case 'owner' : {
        //   const ra = perm.required_auth
        //   if (ra.threshold === 1 && ra.keys.length === 1 && ra.keys[0].weight === 1) {
        //     ownerKeyStr = ra.keys[0].key
        //   }
        //   break
        // }
      }
    })
    // console.log(`activeKeyStr=${activeKeyStr}`)

    let pubKey: Key = Numeric.stringToPublicKey(activeKeyStr)
    if (pubKey.type != Numeric.KeyType.k1 /*&& pubKey.type != Numeric.KeyType.r1*/ ) {
      throw new Error("unsupported public key type")
    }

    const resRows = await this.jsonRpcFetchRows( network.jsonRpc, {
      code: network.registryContract, //DID_REGISTRY_CONTRACT,
      scope: network.registryContract, //DID_REGISTRY_CONTRACT,
      table: 'accdidattr',
      index_position: 1,
      key_type: 'name',
      lower_bound: accountName,
      upper_bound: accountName,
      limit: 1
    })
    // console.log('resAccountDIDAttr = ' + JSON.stringify(resAccountDIDAttr, null, 3))

    let didAttr: { key, value }[] = []
    let deactivated: boolean = false

    if (resRows.length > 0) {
      const didAttrRow = resRows[0]
      didAttr = didAttrRow.attr
    }
    return this.wrapDidDocument(did, pubKey, didAttr, deactivated)
  }

  private wrapDidDocument(
    did: string,
    controllerPubKey: Key,
    pkDidAttr: { key, value }[],
    deactivated: boolean
  ): { didDocument: DIDDocument; deactivated: boolean } {

    const baseDIDDocument: DIDDocument = {
      // '@context': [
      //   'https://www.w3.org/ns/did/v1',
      //   'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld',
      // ],
      '@context': 'https://www.w3.org/ns/did/v1',
      id: did,
      verificationMethod: [],
      authentication: [],
    }

    const publicKeys: VerificationMethod[] = [
      {
        id: `${did}#controller`,
        type: verificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
        controller: did,
        // publicKeyBase58: Numeric.binaryToBase58(controllerPubKey.data)
        publicKeyHex: Buffer.from(controllerPubKey.data).toString('hex')
      },
    ]

    const authentication = [`${did}#controller`]

    const serviceEndpoints: ServiceEndpoint[] = []

    let serviceCount = 0
    pkDidAttr.map(attr => {
      const split = attr.key.split('/')
      if (split.length > 0) {
        const attrType = split[0]
        switch (attrType) {
          case 'svc': {
            serviceCount++
            serviceEndpoints.push({
              id: `${did}#service-${serviceCount}`,
              type: split.length > 1? split[1] : 'AgentService',
              serviceEndpoint: attr.value
            })
            break
          }
        }
      }
    })

    const didDocument: DIDDocument = {
      ...baseDIDDocument,
      verificationMethod: publicKeys,
      authentication: authentication,
    }

    if (serviceEndpoints.length > 0) {
      didDocument.service = serviceEndpoints
    }

    return { didDocument, deactivated }
  }

  private async jsonRpcFetchRows(rpc: JsonRpc, options: object): Promise<any[]> {
    const mergedOptions = {
      json: true,
      limit: 9999,
      ...options,
    };

    const result = await rpc.get_table_rows(mergedOptions);
    return result.rows as any[];
  }
}
