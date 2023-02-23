import InfraSS58DIDResolver from '../infra-ss58-did-resolver'

const someDID = "did:infra:02:5CNMiAMFsH4eq59VQVEWJ3zuTesjht3QRBxsYCWYHL38nyv9";
const address = 'ws://localhost:9944';
jest.setTimeout(10000)
describe('InfraSS58DID', () => {
    let infraDID: InfraSS58DIDResolver;

    describe('DID onChain test', () => {
        beforeAll(async () => {
            infraDID = await InfraSS58DIDResolver.createAsync(address);

        })
        afterAll(async () => {
            if (infraDID.isConnected) await infraDID.disconnect();
        })

        it('Get DID document', async () =>
            await infraDID.resolve(someDID).then(res => {
                expect(res).toBeDefined();
            })
        )
    })

})