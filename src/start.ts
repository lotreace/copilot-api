#!/usr/bin/env node

import { defineCommand } from "citty"
import clipboard from "clipboardy"
import consola from "consola"
import { serve, type ServerHandler } from "srvx"
import invariant from "tiny-invariant"

import type { NtlmCredentials } from "./lib/proxy-ntlm"

import { ensurePaths } from "./lib/paths"
import { initProxy } from "./lib/proxy"
import { generateEnvScript } from "./lib/shell"
import { state } from "./lib/state"
import { setupCopilotToken, setupGitHubToken } from "./lib/token"
import { cacheModels, cacheVSCodeVersion } from "./lib/utils"
import { server } from "./server"

interface RunServerOptions {
  port: number
  verbose: boolean
  accountType: string
  manual: boolean
  rateLimit?: number
  rateLimitWait: boolean
  githubToken?: string
  claudeCode: boolean
  showToken: boolean
  proxyEnv: boolean
  proxyType: "basic" | "ntlm"
  proxyUrl?: string
  proxyCredentials?: string
}

function parseNtlmCredentials(raw?: string): NtlmCredentials {
  if (raw) {
    const backslashIdx = raw.indexOf("\\")
    const colonIdx = raw.indexOf(":", backslashIdx !== -1 ? backslashIdx : 0)

    if (backslashIdx === -1 || colonIdx === -1) {
      throw new Error(
        String.raw`Invalid --proxy-credentials format. Expected: domain\username:password`,
      )
    }

    return {
      domain: raw.slice(0, Math.max(0, backslashIdx)),
      username: raw.slice(backslashIdx + 1, colonIdx),
      password: raw.slice(Math.max(0, colonIdx + 1)),
    }
  }

  const domain = process.env.PROXY_DOMAIN
  const username = process.env.PROXY_USER
  const password = process.env.PROXY_PASS

  if (!domain || !username || !password) {
    throw new Error(
      String.raw`NTLM proxy requires credentials. Use --proxy-credentials domain\username:password or set PROXY_DOMAIN, PROXY_USER, PROXY_PASS environment variables`,
    )
  }

  return { domain, username, password }
}

export async function runServer(options: RunServerOptions): Promise<void> {
  if (options.proxyEnv) {
    const credentials =
      options.proxyType === "ntlm" ?
        parseNtlmCredentials(options.proxyCredentials)
      : undefined
    initProxy({
      proxyType: options.proxyType,
      proxyUrl: options.proxyUrl,
      credentials,
    })
  }

  if (options.verbose) {
    consola.level = 5
    consola.info("Verbose logging enabled")
  }

  state.accountType = options.accountType
  if (options.accountType !== "individual") {
    consola.info(`Using ${options.accountType} plan GitHub account`)
  }

  state.manualApprove = options.manual
  state.rateLimitSeconds = options.rateLimit
  state.rateLimitWait = options.rateLimitWait
  state.showToken = options.showToken

  await ensurePaths()
  await cacheVSCodeVersion()

  if (options.githubToken) {
    state.githubToken = options.githubToken
    consola.info("Using provided GitHub token")
  } else {
    await setupGitHubToken()
  }

  await setupCopilotToken()
  await cacheModels()

  consola.info(
    `Available models: \n${state.models?.data.map((model) => `- ${model.id}`).join("\n")}`,
  )

  const serverUrl = `http://localhost:${options.port}`

  if (options.claudeCode) {
    invariant(state.models, "Models should be loaded by now")

    const selectedModel = await consola.prompt(
      "Select a model to use with Claude Code",
      {
        type: "select",
        options: state.models.data.map((model) => model.id),
      },
    )

    const selectedSmallModel = await consola.prompt(
      "Select a small model to use with Claude Code",
      {
        type: "select",
        options: state.models.data.map((model) => model.id),
      },
    )

    const command = generateEnvScript(
      {
        ANTHROPIC_BASE_URL: serverUrl,
        ANTHROPIC_AUTH_TOKEN: "dummy",
        ANTHROPIC_MODEL: selectedModel,
        ANTHROPIC_DEFAULT_SONNET_MODEL: selectedModel,
        ANTHROPIC_SMALL_FAST_MODEL: selectedSmallModel,
        ANTHROPIC_DEFAULT_HAIKU_MODEL: selectedSmallModel,
        DISABLE_NON_ESSENTIAL_MODEL_CALLS: "1",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      },
      "claude",
    )

    try {
      clipboard.writeSync(command)
      consola.success("Copied Claude Code command to clipboard!")
    } catch {
      consola.warn(
        "Failed to copy to clipboard. Here is the Claude Code command:",
      )
      consola.log(command)
    }
  }

  consola.box(
    `🌐 Usage Viewer: https://ericc-ch.github.io/copilot-api?endpoint=${serverUrl}/usage`,
  )

  serve({
    fetch: server.fetch as ServerHandler,
    port: options.port,
  })
}

export const start = defineCommand({
  meta: {
    name: "start",
    description: "Start the Copilot API server",
  },
  args: {
    port: {
      alias: "p",
      type: "string",
      default: "4141",
      description: "Port to listen on",
    },
    verbose: {
      alias: "v",
      type: "boolean",
      default: false,
      description: "Enable verbose logging",
    },
    "account-type": {
      alias: "a",
      type: "string",
      default: "individual",
      description: "Account type to use (individual, business, enterprise)",
    },
    manual: {
      type: "boolean",
      default: false,
      description: "Enable manual request approval",
    },
    "rate-limit": {
      alias: "r",
      type: "string",
      description: "Rate limit in seconds between requests",
    },
    wait: {
      alias: "w",
      type: "boolean",
      default: false,
      description:
        "Wait instead of error when rate limit is hit. Has no effect if rate limit is not set",
    },
    "github-token": {
      alias: "g",
      type: "string",
      description:
        "Provide GitHub token directly (must be generated using the `auth` subcommand)",
    },
    "claude-code": {
      alias: "c",
      type: "boolean",
      default: false,
      description:
        "Generate a command to launch Claude Code with Copilot API config",
    },
    "show-token": {
      type: "boolean",
      default: false,
      description: "Show GitHub and Copilot tokens on fetch and refresh",
    },
    "proxy-env": {
      type: "boolean",
      default: false,
      description: "Initialize proxy from environment variables",
    },
    "proxy-type": {
      type: "string",
      default: "basic",
      description:
        "Proxy authentication type: basic or ntlm (requires --proxy-env)",
    },
    "proxy-url": {
      type: "string",
      description:
        "Proxy server URL, e.g. http://proxy.corp.com:8080 (falls back to HTTPS_PROXY/HTTP_PROXY env vars)",
    },
    "proxy-credentials": {
      type: "string",
      description: String.raw`NTLM proxy credentials in domain\username:password format (or use PROXY_DOMAIN/PROXY_USER/PROXY_PASS env vars)`,
    },
  },
  run({ args }) {
    const rateLimitRaw = args["rate-limit"]
    const rateLimit =
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      rateLimitRaw === undefined ? undefined : Number.parseInt(rateLimitRaw, 10)

    return runServer({
      port: Number.parseInt(args.port, 10),
      verbose: args.verbose,
      accountType: args["account-type"],
      manual: args.manual,
      rateLimit,
      rateLimitWait: args.wait,
      githubToken: args["github-token"],
      claudeCode: args["claude-code"],
      showToken: args["show-token"],
      proxyEnv: args["proxy-env"],
      proxyType: args["proxy-type"] as "basic" | "ntlm",
      proxyUrl: args["proxy-url"],
      proxyCredentials: args["proxy-credentials"],
    })
  },
})
