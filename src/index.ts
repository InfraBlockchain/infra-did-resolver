import { getResolver } from './infra-did-resolver'
import {
  DEFAULT_REGISTRY_CONTRACT,
  legacyAlgoMap,
  legacyAttrTypes,
  verificationMethodTypes,
  Errors,
} from './typedefs'

export {
  DEFAULT_REGISTRY_CONTRACT as REGISTRY,
  getResolver,
  /**@deprecated */
  legacyAlgoMap as delegateTypes,
  /**@deprecated */
  legacyAttrTypes as attrTypes,
  verificationMethodTypes,
  Errors,
}
