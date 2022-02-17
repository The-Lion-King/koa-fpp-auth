import Fpp from 'fpp-node-api';

export const KOA_USER_AGENT_PREFIX = 'Koa Fpp Auth';

export default function setUserAgent() {
  if (!Fpp.Context.USER_AGENT_PREFIX) {
    Fpp.Context.USER_AGENT_PREFIX = KOA_USER_AGENT_PREFIX;
  } else if (
    !Fpp.Context.USER_AGENT_PREFIX.includes(KOA_USER_AGENT_PREFIX)
  ) {
    Fpp.Context.USER_AGENT_PREFIX = `${Fpp.Context.USER_AGENT_PREFIX} | ${KOA_USER_AGENT_PREFIX}`;
  }
}
