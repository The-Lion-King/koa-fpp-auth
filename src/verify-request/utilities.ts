import {Context} from 'koa';

import Fpp from 'fpp-node-api';

import {Routes} from './types';
import {AccessMode} from '../types';
import {DEFAULT_ACCESS_MODE} from '../auth';

export function redirectToAuth(
  {fallbackRoute, authRoute}: Routes,
  ctx: Context,
) {
  const {
    query: {shop},
  } = ctx;

  const routeForRedirect =
    shop == null ? fallbackRoute : `${authRoute}?shop=${shop}`;

  ctx.redirect(routeForRedirect);
}

export async function clearSession(
  ctx: Context,
  accessMode: AccessMode = DEFAULT_ACCESS_MODE,
) {
  try {
    await Fpp.Utils.deleteCurrentSession(
      ctx.req,
      ctx.res,
      accessMode === 'online',
    );
  } catch (error) {
    if (error instanceof Fpp.Errors.SessionNotFound) {
      // We can just move on if no sessions were cleared
    } else {
      throw error;
    }
  }
}
