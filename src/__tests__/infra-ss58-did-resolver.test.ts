import InfraSS58DIDResolver from '../infra-ss58-did-resolver'

const testDID = 'did:infra:02:5FHF9o59KFv5NCFZ25rqyE4aJ8WGjAfUdpHBVXkQNGHDQ5d2';
const address = 'ws://localhost:9944';
jest.setTimeout(10000)
describe('InfraSS58DID', () => {
    let resolver: InfraSS58DIDResolver;
    describe('DID onChain test', () => {
        beforeAll(async () => {
            resolver = await InfraSS58DIDResolver.createAsync(address);
        })
        afterAll(async () => {
            if (resolver.isConnected) {
                await resolver.disconnect();
            }
        })

        it('Get DID documents', async () =>
            await resolver.resolve(testDID).then(doc => {
                console.log(doc);
                expect(doc).toBeDefined();
            })
        )
    })

})