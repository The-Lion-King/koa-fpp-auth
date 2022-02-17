import {Context} from 'koa';

import {OAuthStartOptions, AccessMode, NextFunction} from '../types';

import getCookieOptions from './cookie-options';
import createEnableCookies from './create-enable-cookies';
import createTopLevelOAuthRedirect from './create-top-level-oauth-redirect';
import createRequestStorageAccess from './create-request-storage-access';
import setUserAgent from './set-user-agent';

import Fpp from 'fpp-node-api';

const DEFAULT_MYFPP_DOMAIN = 'myfunpinpin.com';
export const DEFAULT_ACCESS_MODE: AccessMode = 'online';

export const TOP_LEVEL_OAUTH_COOKIE_NAME = 'fppTopLevelOAuth';
export const TEST_COOKIE_NAME = 'fppTestCookie';
export const GRANTED_STORAGE_ACCESS_COOKIE_NAME =
  'fpp.granted_storage_access';

function hasCookieAccess({cookies}: Context) {
  return Boolean(cookies.get(TEST_COOKIE_NAME));
}

function grantedStorageAccess({cookies}: Context) {
  return Boolean(cookies.get(GRANTED_STORAGE_ACCESS_COOKIE_NAME));
}

function shouldPerformInlineOAuth({cookies}: Context) {
  return Boolean(cookies.get(TOP_LEVEL_OAUTH_COOKIE_NAME));
}

export default function createFppAuth(options: OAuthStartOptions) {
  const config = {
    prefix: '',
    myFppDomain: DEFAULT_MYFPP_DOMAIN,
    accessMode: DEFAULT_ACCESS_MODE,
    ...options,
  };

  const {prefix} = config;

  const oAuthStartPath = `${prefix}/auth`;
  const oAuthCallbackPath = `${oAuthStartPath}/callback`;

  const inlineOAuthPath = `${prefix}/auth/inline`;
  const topLevelOAuthRedirect = createTopLevelOAuthRedirect(
    Fpp.Context.API_KEY,
    inlineOAuthPath,
  );

  const enableCookiesPath = `${oAuthStartPath}/enable_cookies`;
  const enableCookies = createEnableCookies(config);
  const requestStorageAccess = createRequestStorageAccess(config);

  setUserAgent();

  return async function fppAuth(ctx: Context, next: NextFunction) {
    ctx.cookies.secure = true;

    if (
      ctx.path === oAuthStartPath &&
      !hasCookieAccess(ctx) &&
      !grantedStorageAccess(ctx)
    ) {
      await requestStorageAccess(ctx);
      return;
    }

    if (
      ctx.path === inlineOAuthPath ||
      (ctx.path === oAuthStartPath && shouldPerformInlineOAuth(ctx))
    ) {
      const shop = ctx.query.shop;
      if (shop == null) {
        ctx.throw(400);
      }

      ctx.cookies.set(TOP_LEVEL_OAUTH_COOKIE_NAME, '', getCookieOptions(ctx));
      const redirectUrl = await Fpp.Auth.beginAuth(
        ctx.req,
        ctx.res,
        shop,
        oAuthCallbackPath,
        config.accessMode === 'online',
      );
      ctx.redirect(redirectUrl);
      return;
    }

    if (ctx.path === oAuthStartPath) {
      await topLevelOAuthRedirect(ctx);
      return;
    }

    if (ctx.path === oAuthCallbackPath) {
      try {
        await Fpp.Auth.validateAuthCallback(ctx.req, ctx.res, ctx.query);

        ctx.state.fpp = await Fpp.Utils.loadCurrentSession(
          ctx.req,
          ctx.res,
          config.accessMode === 'online',
        );

        if (config.afterAuth) {
          await config.afterAuth(ctx);
        }
      } catch (e) {
        switch (true) {
          case e instanceof Fpp.Errors.InvalidOAuthError:
            ctx.throw(400, e.message);
            break;
          case e instanceof Fpp.Errors.CookieNotFound:
          case e instanceof Fpp.Errors.SessionNotFound:
            // This is likely because the OAuth session cookie expired before the merchant approved the request
            ctx.redirect(`${oAuthStartPath}?shop=${ctx.query.shop}`);
            break;
          default:
            ctx.throw(500, e.message);
            break;
        }
      }
      return;
    }

    if (ctx.path === enableCookiesPath) {
      await enableCookies(ctx);
      return;
    }

    await next();
  };
}

export {default as Error} from './errors';
