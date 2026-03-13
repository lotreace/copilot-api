import consola from "consola"
import {
  GSS_MECH_OID_SPNEGO,
  initializeClient,
  type KerberosClient,
} from "kerberos"
import net from "node:net"
import tls from "node:tls"
import { Agent, type Dispatcher } from "undici"

interface TunnelEntry {
  socket: tls.TLSSocket
  agent: Agent
}

/**
 * Parse an HTTP response from a raw buffer.
 * Returns null if headers are incomplete.
 */
function parseHttpResponse(buf: Buffer): {
  statusCode: number
  headers: Record<string, string>
} | null {
  const headerEnd = buf.indexOf("\r\n\r\n")
  if (headerEnd === -1) return null

  const headerStr = buf.subarray(0, headerEnd).toString("ascii")
  const lines = headerStr.split("\r\n")
  const statusLine = lines[0] ?? ""
  const statusMatch = /^HTTP\/\d\.\d (\d{3})/.exec(statusLine)
  if (!statusMatch) {
    throw new Error(`Invalid HTTP response: ${statusLine}`)
  }

  const headers: Record<string, string> = {}
  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i]?.indexOf(":") ?? -1
    if (colonIdx > 0) {
      const key = lines[i].slice(0, Math.max(0, colonIdx)).trim().toLowerCase()
      const value = lines[i].slice(Math.max(0, colonIdx + 1)).trim()
      headers[key] = value
    }
  }

  return {
    statusCode: Number.parseInt(statusMatch[1], 10),
    headers,
  }
}

function readHttpResponse(
  socket: net.Socket,
): Promise<{ statusCode: number; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const chunks: Array<Buffer> = []

    const onData = (chunk: Buffer) => {
      chunks.push(chunk)
      const combined = Buffer.concat(chunks)
      const parsed = parseHttpResponse(combined)
      if (parsed) {
        cleanup()
        resolve(parsed)
      }
    }

    const onError = (err: Error) => {
      cleanup()
      reject(err)
    }

    const onClose = () => {
      cleanup()
      reject(new Error("Socket closed before HTTP response was complete"))
    }

    function cleanup() {
      socket.removeListener("data", onData)
      socket.removeListener("error", onError)
      socket.removeListener("close", onClose)
    }

    socket.on("data", onData)
    socket.on("error", onError)
    socket.on("close", onClose)
  })
}

interface ConnectOptions {
  socket: net.Socket
  host: string
  port: number
  authHeader?: string
}

function sendConnect(opts: ConnectOptions): void {
  let req = `CONNECT ${opts.host}:${opts.port} HTTP/1.1\r\nHost: ${opts.host}:${opts.port}\r\nProxy-Connection: keep-alive\r\n`
  if (opts.authHeader) {
    req += `Proxy-Authorization: ${opts.authHeader}\r\n`
  }
  req += "\r\n"
  opts.socket.write(req)
}

function connectToProxy(
  proxyHost: string,
  proxyPort: number,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(proxyPort, proxyHost, () => {
      resolve(socket)
    })
    socket.on("error", reject)
  })
}

/**
 * Extract the Negotiate token from a Proxy-Authenticate header value.
 * Returns the base64 server token, or empty string if none.
 */
function extractNegotiateToken(headerValue: string): string {
  const match = /Negotiate\s+(\S+)/i.exec(headerValue)
  return match?.[1] ?? ""
}

interface NegotiateTunnelOptions {
  proxyHost: string
  proxyPort: number
  targetHost: string
  targetPort: number
  spn: string
}

async function createNegotiateTunnel(
  opts: NegotiateTunnelOptions,
): Promise<tls.TLSSocket> {
  const { proxyHost, proxyPort, targetHost, targetPort, spn } = opts

  consola.debug(
    `Negotiate tunnel: connecting to proxy ${proxyHost}:${proxyPort} for ${targetHost}:${targetPort}`,
  )

  const socket = await connectToProxy(proxyHost, proxyPort)

  // Initialize SPNEGO client using system credentials (SSPI on Windows, GSSAPI on Linux)
  consola.debug(`Negotiate tunnel: initializing SPNEGO client (SPN: ${spn})`)
  let client: KerberosClient
  try {
    client = await initializeClient(spn, { mechOID: GSS_MECH_OID_SPNEGO })
  } catch (err: unknown) {
    socket.destroy()
    const msg = err instanceof Error ? err.message : String(err)
    throw new Error(`Failed to initialize Kerberos/SSPI client: ${msg}`)
  }

  // Step 1: Get initial token from SSPI/GSSAPI
  consola.debug("Negotiate tunnel: generating initial SPNEGO token")
  const initialToken = await client.step("")
  sendConnect({
    socket,
    host: targetHost,
    port: targetPort,
    authHeader: `Negotiate ${initialToken}`,
  })

  // Step 2: Read proxy response — may be 200 (done) or 407 (needs more steps)
  const response1 = await readHttpResponse(socket)
  consola.debug(
    `Negotiate tunnel: proxy responded with ${response1.statusCode}`,
  )

  if (response1.statusCode === 200) {
    consola.debug("Negotiate tunnel: authenticated on first step")
    return upgradeToTls(socket, targetHost)
  }

  if (response1.statusCode !== 407) {
    socket.destroy()
    throw new Error(
      `Proxy returned unexpected status ${response1.statusCode} during Negotiate auth`,
    )
  }

  // Multi-leg negotiation — process server challenge
  const proxyAuth = response1.headers["proxy-authenticate"]
  if (!proxyAuth || !/Negotiate/i.test(proxyAuth)) {
    socket.destroy()
    throw new Error(
      `Proxy returned 407 but no Negotiate challenge in Proxy-Authenticate: ${proxyAuth || "(missing)"}`,
    )
  }

  const serverToken = extractNegotiateToken(proxyAuth)
  consola.debug(
    `Negotiate tunnel: processing server challenge (${serverToken.length} chars)`,
  )

  const responseToken = await client.step(serverToken)
  consola.debug(
    `Negotiate tunnel: sending response token (contextComplete: ${client.contextComplete})`,
  )

  sendConnect({
    socket,
    host: targetHost,
    port: targetPort,
    authHeader: `Negotiate ${responseToken}`,
  })

  const response2 = await readHttpResponse(socket)
  consola.debug(
    `Negotiate tunnel: proxy responded with ${response2.statusCode}`,
  )

  if (response2.statusCode === 407) {
    socket.destroy()
    throw new Error(
      "Negotiate authentication rejected — check Kerberos ticket (klist) or Windows login session",
    )
  }

  if (response2.statusCode !== 200) {
    socket.destroy()
    throw new Error(
      `Proxy returned unexpected status ${response2.statusCode} after Negotiate auth`,
    )
  }

  consola.debug("Negotiate tunnel: connection established, upgrading to TLS")
  return upgradeToTls(socket, targetHost)
}

function upgradeToTls(
  socket: net.Socket,
  servername: string,
): Promise<tls.TLSSocket> {
  const tlsSocket = tls.connect({ socket, servername })

  return new Promise((resolve, reject) => {
    tlsSocket.on("secureConnect", () => {
      consola.debug(
        `Negotiate tunnel: TLS handshake complete for ${servername}`,
      )
      resolve(tlsSocket)
    })
    tlsSocket.on("error", (err: Error) => {
      reject(new Error(`TLS handshake failed: ${err.message}`))
    })
  })
}

interface TunnelPool {
  tunnels: Map<string, TunnelEntry>
  pending: Map<string, Promise<TunnelEntry>>
  proxyHost: string
  proxyPort: number
  spn: string
}

async function getOrCreateTunnel(
  pool: TunnelPool,
  targetHost: string,
  targetPort: number,
): Promise<TunnelEntry> {
  const key = `${targetHost}:${targetPort}`

  const existing = pool.tunnels.get(key)
  if (existing && !existing.socket.destroyed) {
    return existing
  }
  pool.tunnels.delete(key)

  const pendingEntry = pool.pending.get(key)
  if (pendingEntry) {
    return pendingEntry
  }

  const promise = (async () => {
    try {
      const tlsSocket = await createNegotiateTunnel({
        proxyHost: pool.proxyHost,
        proxyPort: pool.proxyPort,
        targetHost,
        targetPort,
        spn: pool.spn,
      })

      const agent = new Agent({
        connect: (() =>
          tlsSocket as unknown as net.Socket) as unknown as Agent.Options["connect"],
      })

      const entry: TunnelEntry = { socket: tlsSocket, agent }
      pool.tunnels.set(key, entry)

      tlsSocket.on("close", () => {
        pool.tunnels.delete(key)
      })

      return entry
    } finally {
      pool.pending.delete(key)
    }
  })()

  pool.pending.set(key, promise)
  return promise
}

async function cleanupTunnels(
  pool: TunnelPool,
  method: "close" | "destroy",
): Promise<void> {
  for (const entry of pool.tunnels.values()) {
    entry.socket.destroy()
    await entry.agent[method]()
  }
  pool.tunnels.clear()
}

/**
 * Create an undici dispatcher that routes HTTPS requests through a
 * Negotiate/Kerberos-authenticating proxy using SSPI (Windows) or GSSAPI (Linux).
 * No credentials required — uses the system's Kerberos ticket / Windows login session.
 */
export function createNegotiateDispatcher(proxyUrl: string): {
  dispatch: Dispatcher["dispatch"]
  close: () => Promise<void>
  destroy: () => Promise<void>
} {
  const parsedProxy = new URL(proxyUrl)
  const proxyHost = parsedProxy.hostname
  const proxyPort = Number.parseInt(parsedProxy.port || "8080", 10)

  // SPN must use the FQDN hostname, not an IP address
  const spn = `HTTP@${proxyHost}`

  const pool: TunnelPool = {
    tunnels: new Map(),
    pending: new Map(),
    proxyHost,
    proxyPort,
    spn,
  }

  const directAgent = new Agent()

  return {
    dispatch(
      options: Dispatcher.DispatchOptions,
      handler: Dispatcher.DispatchHandler,
    ) {
      const origin =
        typeof options.origin === "string" ?
          new URL(options.origin)
        : (options.origin as URL)

      if (origin.protocol !== "https:") {
        consola.debug(`Negotiate proxy bypass (non-HTTPS): ${origin.hostname}`)
        return (directAgent as unknown as Dispatcher).dispatch(options, handler)
      }

      const targetHost = origin.hostname
      const targetPort = Number.parseInt(origin.port || "443", 10)

      getOrCreateTunnel(pool, targetHost, targetPort)
        .then((entry) => {
          consola.debug(
            `Negotiate proxy route: ${targetHost}:${targetPort} via ${proxyHost}:${proxyPort}`,
          )
          ;(entry.agent as unknown as Dispatcher).dispatch(options, handler)
        })
        .catch((err: unknown) => {
          pool.tunnels.delete(`${targetHost}:${targetPort}`)
          const error = err instanceof Error ? err : new Error(String(err))
          consola.error(
            `Negotiate proxy error for ${targetHost}: ${error.message}`,
          )
          // eslint-disable-next-line @typescript-eslint/no-deprecated
          handler.onError?.(error)
        })

      return false
    },
    async close() {
      await cleanupTunnels(pool, "close")
      await directAgent.close()
    },
    async destroy() {
      await cleanupTunnels(pool, "destroy")
      await directAgent.destroy()
    },
  }
}
