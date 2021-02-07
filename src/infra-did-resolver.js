import BN from 'bn.js'
import { Buffer } from 'buffer'


import { JsonRpc, Numeric } from 'eosjs'
import fetch from 'node-fetch'

const DID_REGISTRY_CONTRACT = 'infradidregi'

export const rpc = new JsonRpc("http://localhost:8888", { fetch } );

export async function jsonRpcFetchRows(options) {
  const mergedOptions = {
    json: true,
    limit: 9999,
    ...options,
  };

  const result = await rpc.get_table_rows(mergedOptions);

  return result.rows;
}

// function accountDidDocument(did, activePubKey, pkDidAttr) {
//
// }

function pubkeyDidDocument(did, controllerPubKey, pkDidAttr) {

  const publicKey = [
    {
      id: `${did}#controller`,
      type: 'Secp256k1VerificationKey2018',
      controller: did,
      publicKeyHex: Buffer.from(controllerPubKey.data).toString('hex')
    }
  ]

  const authentication = [
    {
      type: 'Secp256k1SignatureAuthentication2018',
      publicKey: `${did}#controller`
    }
  ]

  const serviceEndpoints = []

  pkDidAttr.map(attr => {
    const split = attr.key.split('/')
    if (split.length > 0) {
      const attrType = split[0]
      switch (attrType) {
        case 'svc': {
          serviceEndpoints.push({
            type: split.length > 1? split[1] : 'AgentService',
            serviceEndpoint: attr.value
          })
          break
        }
      }
    }
  })

  const doc = {
    '@context': 'https://w3id.org/did/v1',
    id: did,
    publicKey: publicKey, //.concat(Object.values(pks)),
    authentication: authentication, //.concat(Object.values(auth))
  }
  if (serviceEndpoints.length > 0) {
    doc.service = serviceEndpoints
  }

  return doc
}

async function resolvePubKeyDID(did, pubKeyStr) {
  try {
    let pubKey = Numeric.stringToPublicKey(pubKeyStr)
    if (pubKey.type != Numeric.KeyType.k1 /*&& pubKey.type != Numeric.KeyType.r1*/ ) {
      throw new Error("unsupported public key type")
    }
    // console.log(`pubKey=${JSON.stringify(pubKey)}`)

    // console.log(Buffer.from(pubKey.data).toString('hex'));
    // console.log(Buffer.from(pubKey.data.slice(1,pubKey.data.length)).toString('hex'));
    // const result = await rpc.get_table_rows({
    //   json: true,
    //   code: DID_REGISTRY_CONTRACT,
    //   scope: DID_REGISTRY_CONTRACT,
    //   table: 'pubkeydid',
    //   lower_bound: 1,
    //   limit: 10
    // })
    // //get_table_rows({ json, code, scope, table, lower_bound, upper_bound, index_position, key_type, limit, reverse, show_payer, }: any): Promise<any>;
    // console.log(JSON.stringify(result, null, 3))

    const pubkey_index_256bits = Buffer.from(pubKey.data.slice(1,pubKey.data.length)).toString('hex')

    const resPubKeyDID = await jsonRpcFetchRows({
      code: DID_REGISTRY_CONTRACT,
      scope: DID_REGISTRY_CONTRACT,
      table: 'pubkeydid',
      index_position: 2,
      key_type: 'sha256',
      lower_bound: pubkey_index_256bits,
      upper_bound: pubkey_index_256bits,
      limit: 1
    })
    console.log('resPubKeyDID = ' + JSON.stringify(resPubKeyDID, null, 3))

    let pkDidAttr = []
    let ownerPubKey = null

    if (resPubKeyDID.length > 0) {
      const pubkeyDIDrow = resPubKeyDID[0]
      pkDidAttr = pubkeyDIDrow.attr

      const resPubKeyDIDOwner = await jsonRpcFetchRows({
        json: true,
        code: DID_REGISTRY_CONTRACT,
        scope: DID_REGISTRY_CONTRACT,
        table: 'pkdidowner',
        index_position: 1,
        key_type: 'i64',
        lower_bound: pubkeyDIDrow.pkid,
        limit: 1
      })
      console.log('resPubKeyDIDOwner = ' + JSON.stringify(resPubKeyDIDOwner, null, 3))
      if (resPubKeyDIDOwner.length > 0 && resPubKeyDIDOwner[0].pkid == pubkeyDIDrow.pkid) {
        ownerPubKey = Numeric.stringToPublicKey(resPubKeyDIDOwner[0].owner_pk)
      }
    }

    return pubkeyDidDocument(did, ownerPubKey? ownerPubKey : pubKey, pkDidAttr)

  } catch (e) {
    console.error('error')
    console.error(e)
  }

  return null
}

async function resolveAccountDID(did, accountName) {
  try {
    const res = await rpc.get_account(accountName);
    console.log(JSON.stringify(res, null, 3))

    // let ownerKeyStr
    let activeKeyStr
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
    console.log(`activeKeyStr=${activeKeyStr}`)

    let pubKey = Numeric.stringToPublicKey(activeKeyStr)
    if (pubKey.type != Numeric.KeyType.k1 /*&& pubKey.type != Numeric.KeyType.r1*/ ) {
      throw new Error("unsupported public key type")
    }

    const resAccountDIDAttr = await jsonRpcFetchRows({
      code: DID_REGISTRY_CONTRACT,
      scope: DID_REGISTRY_CONTRACT,
      table: 'accdidattr',
      index_position: 1,
      key_type: 'name',
      lower_bound: accountName,
      upper_bound: accountName,
      limit: 1
    })
    console.log('resAccountDIDAttr = ' + JSON.stringify(resAccountDIDAttr, null, 3))

    let didAttr = []

    if (resAccountDIDAttr.length > 0) {
      const didAttrRow = resAccountDIDAttr[0]
      didAttr = didAttrRow.attr
    }
    return pubkeyDidDocument(did, pubKey, didAttr)
  } catch (e) {
    console.error(e)
    return {}
  }
}


function getResolver(conf = {}) {

  async function resolve(did, parsed) {
    // const fullId = parsed.id.match(identifierMatcher)
    // if (!fullId) throw new Error(`Not a valid ethr DID: ${did}`)
    // const id = fullId[2]
    // const networkId = !fullId[1] ? 'mainnet' : fullId[1].slice(0, -1)
    //
    // if (!networks[networkId]) throw new Error(`No conf for networkId: ${networkId}`)
    //
    // const { controller, history, publicKey } = await changeLog(id, networkId)
    // return wrapDidDocument(did, controller, publicKey, history)
    let didDoc = {}
    try {

      if (parsed.id.startsWith("PUB_K1_") || parsed.id.startsWith("PUB_R1_") || parsed.id.startsWith("EOS")) {
        didDoc = await resolvePubKeyDID(did, parsed.id)
      } else {
        didDoc = await resolveAccountDID(did, parsed.id)
      }


      // let pubKey = Numeric.stringToPublicKey(parsed.id)
      // if (pubKey.type != Numeric.KeyType.k1 && pubKey.type != Numeric.KeyType.r1 ) {
      //   throw new Error("unsupported public key type")
      // }
      // console.log(Buffer.from(pubKey.data).toString('hex'));
      // console.log(Buffer.from(pubKey.data.slice(1,pubKey.data.length)).toString('hex'));
      // const result = await rpc.get_table_rows({
      //   json: true,
      //   code: DID_REGISTRY_CONTRACT,
      //   scope: DID_REGISTRY_CONTRACT,
      //   table: 'pubkeydid',
      //   lower_bound: 1,
      //   limit: 10
      // })
      // //get_table_rows({ json, code, scope, table, lower_bound, upper_bound, index_position, key_type, limit, reverse, show_payer, }: any): Promise<any>;
      // console.log(JSON.stringify(result, null, 3))
      //
      // const pubkey_index_256bits = Buffer.from(pubKey.data.slice(1,pubKey.data.length)).toString('hex')
      //
      // const result2 = await rpc.get_table_rows({
      //   json: true,
      //   code: DID_REGISTRY_CONTRACT,
      //   scope: DID_REGISTRY_CONTRACT,
      //   table: 'pubkeydid',
      //   index_position: 2,
      //   key_type: 'sha256',
      //   lower_bound: pubkey_index_256bits,
      //   upper_bound: pubkey_index_256bits,
      //   limit: 1
      // })
      // console.log(JSON.stringify(result2, null, 3))

    } catch (e) {
      console.error(e)
      return null
    }

    return didDoc
  }

  return { infra: resolve }
}

export {
  DID_REGISTRY_CONTRACT,
  getResolver,
}
