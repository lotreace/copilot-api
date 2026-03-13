import consola from "consola"
import { getProxyForUrl } from "proxy-from-env"
import { Agent, ProxyAgent, setGlobalDispatcher, type Dispatcher } from "undici"

import { createNtlmDispatcher, type NtlmCredentials } from "./proxy-ntlm"

export interface ProxyConfig {
  proxyType: "basic" | "ntlm"
  proxyUrl?: string
  credentials?: NtlmCredentials
}

/**
 * Create a dispatcher that routes requests through basic-auth proxies
 * determined by HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables.
 */
function createBasicProxyDispatcher() {
  const direct = new Agent()
  const proxies = new Map<string, ProxyAgent>()

  return {
    dispatch(
      options: Dispatcher.DispatchOptions,
      handler: Dispatcher.DispatchHandler,
    ) {
      try {
        const origin =
          typeof options.origin === "string" ?
            new URL(options.origin)
          : (options.origin as URL)
        const get = getProxyForUrl as unknown as (
          u: string,
        ) => string | undefined
        const raw = get(origin.toString())
        const proxyUrl = raw && raw.length > 0 ? raw : undefined
        if (!proxyUrl) {
          consola.debug(`HTTP proxy bypass: ${origin.hostname}`)
          return (direct as unknown as Dispatcher).dispatch(options, handler)
        }
        let agent = proxies.get(proxyUrl)
        if (!agent) {
          agent = new ProxyAgent(proxyUrl)
          proxies.set(proxyUrl, agent)
        }
        let label = proxyUrl
        try {
          const u = new URL(proxyUrl)
          label = `${u.protocol}//${u.host}`
        } catch {
          /* noop */
        }
        consola.debug(`HTTP proxy route: ${origin.hostname} via ${label}`)
        return (agent as unknown as Dispatcher).dispatch(options, handler)
      } catch {
        return (direct as unknown as Dispatcher).dispatch(options, handler)
      }
    },
    close() {
      return direct.close()
    },
    destroy() {
      return direct.destroy()
    },
  }
}

/**
 * Initialize proxy support with the given configuration.
 * For NTLM, a single proxy URL is read from HTTPS_PROXY (or HTTP_PROXY).
 */
export function initProxy(config: ProxyConfig): void {
  if (typeof Bun !== "undefined") {
    if (config.proxyType === "ntlm") {
      consola.warn(
        "NTLM proxy is not supported under Bun — run with Node.js instead",
      )
    }
    return
  }

  try {
    if (config.proxyType === "ntlm") {
      if (!config.credentials) {
        throw new Error(
          "NTLM proxy requires credentials — use --proxy-credentials or PROXY_DOMAIN/PROXY_USER/PROXY_PASS env vars",
        )
      }

      // Read proxy URL from config, then fall back to environment
      const proxyUrl =
        config.proxyUrl
        || process.env.HTTPS_PROXY
        || process.env.https_proxy
        || process.env.HTTP_PROXY
        || process.env.http_proxy

      if (!proxyUrl) {
        throw new Error(
          "NTLM proxy requires --proxy-url or HTTPS_PROXY/HTTP_PROXY environment variable to be set",
        )
      }

      const dispatcher = createNtlmDispatcher(proxyUrl, config.credentials)
      setGlobalDispatcher(dispatcher as unknown as Dispatcher)
      consola.debug(
        `NTLM proxy configured via ${new URL(proxyUrl).host} (domain: ${config.credentials.domain})`,
      )
    } else {
      const dispatcher = createBasicProxyDispatcher()
      setGlobalDispatcher(dispatcher as unknown as Dispatcher)
      consola.debug("HTTP proxy configured from environment (per-URL)")
    }
  } catch (err) {
    if (config.proxyType === "ntlm") {
      // NTLM errors should be surfaced, not silently skipped
      throw err
    }
    consola.debug("Proxy setup skipped:", err)
  }
}

/**
 * Backward-compatible alias — initializes basic proxy from environment.
 */
export function initProxyFromEnv(): void {
  initProxy({ proxyType: "basic" })
}
