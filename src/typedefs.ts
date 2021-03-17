import { VerificationMethod } from 'did-resolver'

export const DEFAULT_REGISTRY_CONTRACT = 'infradidregi'
export const DEFAULT_JSON_RPC = 'http://localhost:8888'

export enum verificationMethodTypes {
  EcdsaSecp256k1VerificationKey2019 = 'EcdsaSecp256k1VerificationKey2019',
  EcdsaSecp256k1RecoveryMethod2020 = 'EcdsaSecp256k1RecoveryMethod2020',
  Ed25519VerificationKey2018 = 'Ed25519VerificationKey2018',
  RSAVerificationKey2018 = 'RSAVerificationKey2018',
  X25519KeyAgreementKey2019 = 'X25519KeyAgreementKey2019',
}

export interface LegacyVerificationMethod extends VerificationMethod {
  /**@deprecated */
  publicKeyHex?: string
  /**@deprecated */
  publicKeyBase64?: string
  /**@deprecated */
  publicKeyPem?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export const legacyAttrTypes: Record<string, string> = {
  sigAuth: 'SignatureAuthentication2018',
  veriKey: 'VerificationKey2018',
  enc: 'KeyAgreementKey2019',
}

export const legacyAlgoMap: Record<string, string> = {
  /**@deprecated */
  Secp256k1VerificationKey2018: verificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
  /**@deprecated */
  Ed25519SignatureAuthentication2018: verificationMethodTypes.Ed25519VerificationKey2018,
  /**@deprecated */
  Secp256k1SignatureAuthentication2018: verificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
  //keep legacy mapping
  RSAVerificationKey2018: verificationMethodTypes.RSAVerificationKey2018,
  Ed25519VerificationKey2018: verificationMethodTypes.Ed25519VerificationKey2018,
  X25519KeyAgreementKey2019: verificationMethodTypes.X25519KeyAgreementKey2019,
}

export const INFRA_DID_NONCE_VALUE_FOR_REVOKED_PUB_KEY_DID: number = 65535

export const knownInfraBlockchainNetworks: Record<string, string> = {
  mainnet: '01',
  yosemite: 'yos',
  sentinel: 'sentinel',
}

export enum Errors {
  /**
   * The resolver has failed to construct the DID document.
   * Please inspect the `DIDResolutionMetadata.message` to debug further.
   */
  notFound = 'notFound',

  /**
   * The resolver does not know how to resolve the given DID. Most likely it is not a `did:infra`.
   */
  invalidDid = 'invalidDid',

  /**
   * The resolver is misconfigured or is being asked to resolve a DID anchored on an unknown network
   */
  unknownNetwork = 'unknownNetwork',
}
