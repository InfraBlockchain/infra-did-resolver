import b58 from 'bs58';
import { ApiPromise, Keyring, WsProvider } from '@polkadot/api';
import { HttpProvider } from '@polkadot/rpc-provider';
import { u8aToString, hexToU8a, u8aToHex } from '@polkadot/util';
import { encodeAddress, decodeAddress, } from '@polkadot/util-crypto';
import typesBundle from '@docknetwork/node-types';
import { BTreeSet } from '@polkadot/types';
import { Codec } from '@polkadot/types-codec/types';


class VerificationRelationship {
    constructor(private _value = 0) {}
    get value() { return this._value }
    setAuthentication() { this._value |= 0b0001 } //1
    setAssertion() { this._value |= 0b0010 } //2
    setCapabilityInvocation() { this._value |= 0b0100 } //4
    setKeyAgreement() { this._value |= 0b1000 }//8
    setAllSigning() { this._value |= 0b0111 }//7
    isAuthentication() { return !!(this._value & 0b0001) }
    isAssertion() { return !!(this._value & 0b0010) }
    isCapabilityInvocation() { return !!(this._value & 0b0100) }
    isKeyAgreement() { return !!(this._value & 0b1000) }
}

class ExtrinsicError extends Error {
    constructor(message, private method, private data, private status, private events) {
        super(message);
        this.name = 'ExtrinsicError';
    }
    static getExtrinsicErrorMsg(data, typeDef, api): string {
        let errorMsg = 'Extrinsic failed submission:';
        data.forEach((error) => {
            if (error.isModule) {
                try {
                    const decoded = api.registry.findMetaError(error.asModule);
                    const { docs, method, section } = decoded;
                    errorMsg += `\n${section}.${method}: ${docs.join(' ')}`;
                } catch (e) {
                    errorMsg += `\nError at module index: ${error.asModule.index} Error: ${error.asModule.error}`;
                }
            } else {
                const errorStr = error.toString();
                if (errorStr !== '0') {
                    errorMsg += `\n${errorStr}`;
                }
            }
        });
        return errorMsg;
    }
}

export default class InfraSS58DIDResolver {
    private api;

    private address: string;
    get isConnected(): boolean {
        return this.api && this.api.isConnected || false;
    }

    private constructor() {}
    static async createAsync(address: string): Promise<InfraSS58DIDResolver> {
        return await new InfraSS58DIDResolver().init(address)
    }
    static validateInfraSS58DID(infraSS58DID: string): boolean {
        const didSplit = infraSS58DID.split(':')
        if (didSplit.length !== 4) {
            throw new Error(`invalid infraSS58DID, needs network identifier part and id part (${infraSS58DID})`)
        }

        const regex = new RegExp(/^[5KL][1-9A-HJ-NP-Za-km-z]{47}$/);
        const matches = regex.exec(didSplit[3]);
        if (!matches) {
            throw new Error('The identifier must be 32 bytes and valid SS58 string');
        }
        return true
    }
    private static splitDID(did: string) {
        const splitDID = did.split(':')
        return {
            ss58ID: splitDID.pop(),
            qualifier: splitDID.join(':'),
        }
    }
    private static didToHex(did: string) {
        const { ss58ID } = InfraSS58DIDResolver.splitDID(did);
        return u8aToHex(decodeAddress(ss58ID));
    }

    private async init(address: string): Promise<InfraSS58DIDResolver> {
        if (this.api) {
            if (this.api.isConnected) {
                throw new Error('API is already connected');
            } else {
                await this.disconnect();
            }
        }
        this.address = address || this.address;
        if (this.address && (
            this.address.indexOf('wss://') === -1 && this.address.indexOf('https://') === -1
        )) {
            console.warn(`WARNING: Using non-secure endpoint: ${this.address}`);
        }
        const isWebsocket = this.address && this.address.indexOf('http') === -1;
        const provider = isWebsocket ? new WsProvider(this.address) : new HttpProvider(this.address);
        const apiOptions: any = {
            provider,
            rpc: {},
            typesBundle: typesBundle,
        };
        this.api = await ApiPromise.create(apiOptions);
        return this
    }

    private async getOnchainDIDDetail(hexDid): Promise<{
        nonce: number,
        lastKeyId: number,
        activeControllerKeys: number,
        activeControllers: number
    }> {
        try {
            const resp = await this.api.query.didModule.dids(hexDid)
            if (resp.isNone) { throw new Error("did not exist at onChain") }
            const didDetail = resp.unwrap().asOnChain;
            const data = didDetail.data || didDetail;
            return {
                nonce: didDetail.nonce.toNumber(),
                lastKeyId: data.lastKeyId.toNumber(),
                activeControllerKeys: data.activeControllerKeys.toNumber(),
                activeControllers: data.activeControllers.toNumber(),
            };
        } catch (e) { throw e }
    }

    async resolve(did, { getBbsPlusSigKeys = true } = {}) {
        const hexId = InfraSS58DIDResolver.didToHex(did);
        const { qualifier } = InfraSS58DIDResolver.splitDID(did)
        let didDetails = await this.getOnchainDIDDetail(hexId);
        const attests = await this.api.query.attest.attestations(hexId);
        const ATTESTS_IRI = attests.iri.isSome ? u8aToString(hexToU8a(attests.iri.toString())) : null;
        const id = (did === hexId) ? `${qualifier}${encodeAddress(hexId)}` : did;
        const controllers: any[] = [];
        if (didDetails.activeControllers > 0) {
            const cnts = await this.api.query.didModule.didControllers.entries(hexId);
            cnts.forEach(([key, value]) => {
                if (value.isSome) {
                    const [controlled, controller] = key.toHuman();
                    if (controlled !== hexId) {
                        throw new Error(`Controlled DID ${controlled[0]} was found to be different than queried DID ${hexId}`);
                    }
                    controllers.push(controller);
                }
            });
        }

        const serviceEndpoints: any[] = [];
        const sps = await this.api.query.didModule.didServiceEndpoints.entries(hexId);
        sps.forEach(([key, value]) => {
            if (value.isSome) {
                const sp = value.unwrap();
                const [d, spId] = key.args;
                const d_ = u8aToHex(d);
                if (d_ !== hexId) {
                    throw new Error(`DID ${d_} was found to be different than queried DID ${hexId}`);
                }
                serviceEndpoints.push([spId, sp]);
            }
        });

        const keys: any[] = [];
        const assertion: any[] = [];
        const authn: any[] = [];
        const capInv: any[] = [];
        const keyAgr: any[] = [];
        if (didDetails.lastKeyId > 0) {
            const dks = await this.api.query.didModule.didKeys.entries(hexId);
            dks.forEach(([key, value]) => {
                if (value.isSome) {
                    const dk = value.unwrap();
                    const [d, i] = key.args;
                    const d_ = u8aToHex(d);
                    if (d_ !== hexId) {
                        throw new Error(`DID ${d_} was found to be different than queried DID ${hexId}`);
                    }
                    const index = i.toNumber();
                    const pk = dk.publicKey;
                    let publicKeyRaw;
                    let typ;
                    if (pk.isSr25519) {
                        typ = 'Sr25519VerificationKey2020';
                        publicKeyRaw = pk.asSr25519.value;
                    } else if (pk.isEd25519) {
                        typ = 'Ed25519VerificationKey2018';
                        publicKeyRaw = pk.asEd25519.value;
                    } else {
                        throw new Error(`Cannot parse public key ${pk}`);
                    }
                    keys.push([index, typ, publicKeyRaw]);
                    const vr = new VerificationRelationship(dk.verRels.toNumber());
                    if (vr.isAuthentication()) authn.push(index);
                    if (vr.isAssertion()) assertion.push(index);
                    if (vr.isCapabilityInvocation()) capInv.push(index);
                    if (vr.isKeyAgreement()) keyAgr.push(index);
                }
            });
        }

        if (getBbsPlusSigKeys === true) {
            const { lastKeyId } = didDetails;
            if (lastKeyId > keys.length) {
                const possibleBbsPlusKeyIds = new Set();
                for (let i = 1; i <= lastKeyId; i++) {
                    possibleBbsPlusKeyIds.add(i);
                }
                for (const [i] of keys) {
                    possibleBbsPlusKeyIds.delete(i);
                }

                const queryKeys: any[] = [];
                for (const k of possibleBbsPlusKeyIds) {
                    queryKeys.push([hexId, k]);
                }
                const resp = await this.api.query.bbsPlus.bbsPlusKeys.multi(queryKeys);
                function createPublicKeyObjFromChainResponse(pk) {
                    const pkObj: any = {
                        bytes: u8aToHex(pk.bytes),
                        curveType: null,
                        paramsRef: null,
                    };
                    if (pk.curveType.isBls12381) {
                        pkObj.curveType = 'Bls12381';
                    }
                    if (pk.paramsRef.isSome) {
                        const pr = pk.paramsRef.unwrap();
                        pkObj.paramsRef = [u8aToHex(pr[0]), pr[1].toNumber()];
                    } else {
                        pkObj.paramsRef = null;
                    }
                    return pkObj;
                }
                let currentIter = 0;
                for (const r of resp) {
                    if (r.isSome) {
                        const pkObj = createPublicKeyObjFromChainResponse(r.unwrap());
                        if (pkObj.curveType !== 'Bls12381') {
                            throw new Error(`Curve type should have been Bls12381 but was ${pkObj.curveType}`);
                        }
                        const keyIndex = queryKeys[currentIter][1];
                        keys.push([keyIndex, 'Bls12381G2VerificationKeyDock2022', hexToU8a(pkObj.bytes)]);
                        assertion.push(keyIndex);
                    }
                    currentIter++;
                }
            }
        }

        keys.sort((a, b) => a[0] - b[0]);
        assertion.sort();
        authn.sort();
        capInv.sort();
        keyAgr.sort();

        const verificationMethod = keys.map(([index, typ, publicKeyRaw]) => ({
            id: `${id}#keys-${index}`,
            type: typ,
            controller: id,
            publicKeyBase58: b58.encode(publicKeyRaw),
        }));
        const assertionMethod = assertion.map((i) => `${id}#keys-${i}`);
        const authentication = authn.map((i) => `${id}#keys-${i}`);
        const capabilityInvocation = capInv.map((i) => `${id}#keys-${i}`);
        const keyAgreement = keyAgr.map((i) => `${id}#keys-${i}`);
        let service: any = [];
        if (serviceEndpoints.length > 0) {
            const decoder = new TextDecoder();
            service = serviceEndpoints.map(([spId, sp]) => {
                const spType = sp.types.toNumber();
                if (spType !== 1) {
                    throw new Error(
                        `Only "LinkedDomains" supported as service endpoint type for now but found ${spType}`,
                    );
                }
                return {
                    id: decoder.decode(spId),
                    type: 'LinkedDomains',
                    serviceEndpoint: sp.origins.map((o) => decoder.decode(o)),
                };
            });
        }
        return {
            '@context': ['https://www.w3.org/ns/did/v1'],
            id,
            controller: controllers.map((c) => `${qualifier}${encodeAddress(c)}`),
            publicKey: verificationMethod,
            authentication,
            assertionMethod,
            keyAgreement,
            capabilityInvocation,
            ATTESTS_IRI,
            service,
        };
    }

    async disconnect() {
        if (this.api) {
            if (this.api.isConnected) {
                await this.api.disconnect();
            }
            delete this.api;
        }
    }
    async readyTest() {
        if (this.address !== 'ws://localhost:9944') throw new Error('test function only for localhost:9944')
        const did = "did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2";
        const didKey = {
            publicKey: {
                Ed25519: '0x6bf52713a6da68680bc51097382f6fc4058c2600e7a924169100c93179c1f4ce',
            },
            verRels: { _value: 0 }
        }
        await this.registerOnChainForTest(did, didKey);
        return did
    }
    async endTest() {
        if (this.address !== 'ws://localhost:9944') throw new Error('test function only for localhost:9944')
        const did = "did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2";
        const seed = '0x92395960e119d5d2e68d33d932a7aea00fe316da6d4f2939e417a4c290163e7e'
        const keypair = (new Keyring({ type: 'ed25519' })).addFromSeed(hexToU8a(seed))
        await this.unregisterOnChainForTest(did, keypair);
    }

    private async registerOnChainForTest(did, didKey) {
        const accountKeyPair = (new Keyring({ type: 'sr25519' })).addFromUri('//Alice');
        try {
            const hexId: unknown = InfraSS58DIDResolver.didToHex(did)
            const didKeys = [didKey];//.map((d) => d.toJSON());
            const controllers = new BTreeSet(undefined, undefined, undefined)
            controllers.add(hexId as Codec)
            const tx = await this.api.tx.didModule.newOnchain(hexId, didKeys, controllers);
            return this.signAndSend(accountKeyPair, tx, false, {});
        } catch (e) { throw e }
    }
    private async unregisterOnChainForTest(did, keypair) {
        const accountKeyPair = (new Keyring({ type: 'sr25519' })).addFromUri('//Alice');
        try {
            const hexDID = InfraSS58DIDResolver.didToHex(did)
            const nonce = await this.getOnchainDIDDetail(hexDID).then(res => res.nonce + 1);
            const DidRemoval = { did: hexDID, nonce };
            const stateMessage = this.api.createType('StateChange', { DidRemoval }).toU8a();
            const controllerDIDSig = {
                did: InfraSS58DIDResolver.didToHex(did),
                keyId: 1,
                sig: { Ed25519: u8aToHex(keypair.sign(stateMessage)) }
            }
            const tx = await this.api.tx.didModule.removeOnchainDid(DidRemoval, controllerDIDSig);
            return this.signAndSend(accountKeyPair, tx, false, {});
        } catch (e) { throw e }
    }

    private async send(extrinsic, waitForFinalization = true) {
        const sendPromise = new Promise((resolve, reject) => {
            try {
                let unsubFunc = () => {};
                return extrinsic
                    .send((extrResult) => {
                        const { events = [], status } = extrResult;
                        for (let i = 0; i < events.length; i++) {
                            const {
                                event: {
                                    data, method, typeDef,
                                },
                            } = events[i];
                            if (method === 'ExtrinsicFailed' || method === 'BatchInterrupted') {
                                const errorMsg = ExtrinsicError.getExtrinsicErrorMsg(data, typeDef, this.api);
                                const error = new ExtrinsicError(errorMsg, method, data, status, events);
                                reject(error);
                                return error;
                            }
                        }
                        if ((waitForFinalization && status.isFinalized) || (!waitForFinalization && status.isInBlock)) {
                            unsubFunc();
                            resolve(extrResult);
                        }
                        return extrResult;
                    })
                    .catch((error) => { reject(error) })
                    .then((unsub) => { unsubFunc = unsub });
            } catch (error) { reject(error) }
            return this;
        });
        return await sendPromise;
    }
    private async signAndSend(accountKeyPair, extrinsic, waitForFinalization = true, params = {}) {
        // @ts-ignore
        params.nonce = await this.api.rpc.system.accountNextIndex(accountKeyPair.address);
        const signedExtrinsic = await extrinsic.signAsync(accountKeyPair, params)
        return this.send(signedExtrinsic, waitForFinalization);
    }
}
