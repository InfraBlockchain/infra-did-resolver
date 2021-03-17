import { JsonRpc } from "eosjs";
import fetch from 'node-fetch'

/**
 * A configuration entry for an InfraBlockchain network
 *
 * @example ```js
 *   {
 *      networkId: '01',
 *      registryContract: 'infradidregi',
 *      rpcEndpoint: 'http://localhost:8888'
 *   }
 * ```
 */
export interface NetworkConfiguration {
  networkId: string
  registryContract: string
  rpcEndpoint: string
}

export interface MultiNetworkConfiguration {
  networks?: NetworkConfiguration[]
}

export type ConfigurationOptions = MultiNetworkConfiguration

export interface ConfiguredNetwork {
  jsonRpc: JsonRpc,
  registryContract: string
}

export type ConfiguredNetworks = Record<string, ConfiguredNetwork>

function configureNetwork(net: NetworkConfiguration) : ConfiguredNetwork {
  const registryContract = net.registryContract
  const jsonRpc = new JsonRpc(net.rpcEndpoint, { fetch } );
  return { jsonRpc, registryContract }
}

function configureNetworks(conf: MultiNetworkConfiguration) : ConfiguredNetworks {
  const networks = {}
  for (let i = 0; i < conf.networks.length; i++) {
    const net = conf.networks[i]
    networks[net.networkId] = configureNetwork(net)
    if (networks[net.networkId] === null) {
      console.warn(`invalid configuration for ${net.networkId}`)
    }
  }
  return networks
}

export function configureResolverWithNetworks(conf: ConfigurationOptions = {}): ConfiguredNetworks {
  const networks = {
    ...configureNetworks(conf)
  }
  for (const expectedNet of conf.networks) {
    if (!networks[expectedNet.networkId]) {
      throw new Error(
        `Chain network configuration for ${expectedNet.networkId} was attempted but no valid configuration was provided`
      )
    }
  }
  if (Object.keys(networks).length === 0) {
    throw new Error('InfraDIDResolver requires a provider configuration for at least one network')
  }
  return networks
}
