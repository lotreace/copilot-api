import consola from "consola"
import net from "node:net"
import tls from "node:tls"
import ntlm from "ntlm-client"
import { Agent, type Dispatcher } from "undici"

export interface NtlmCredentials {
  domain: string
  username: string
  password: string
  workstation?: string
}

interface TunnelEntry {
  socket: tls.TLSSocket
  agent: Agent
}

/**
 * Parse an HTTP response from a raw buffer.
 * Returns null if headers are incomplete (no \r\n\r\n yet).
 */
function parseHttpResponse(buf: Buffer): {
  statusCode: number
  headers: Record<string, string>
  headerEndIndex: number
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
    headerEndIndex: headerEnd + 4,
  }
}

/**
 * Read from a socket until we have a complete HTTP response header.
 */
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
        socket.removeListener("data", onData)
        socket.removeListener("error", onError)
        socket.removeListener("close", onClose)
        resolve({ statusCode: parsed.statusCode, headers: parsed.headers })
      }
    }

    const onError = (err: Error) => {
      socket.removeListener("data", onData)
      socket.removeListener("close", onClose)
      reject(err)
    }

    const onClose = () => {
      socket.removeListener("data", onData)
      socket.removeListener("error", onError)
      reject(new Error("Socket closed before HTTP response was complete"))
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
  let req = `CONNECT ${opts.host}:${opts.port} HTTP/1.1\r\nHost: ${opts.host}:${opts.port}\r\n`
  if (opts.authHeader) {
    req += `Proxy-Authorization: ${opts.authHeader}\r\n`
  }
  req += "\r\n"
  opts.socket.write(req)
}

/**
 * Open a TCP connection to the proxy.
 */
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

interface TunnelOptions {
  proxyHost: string
  proxyPort: number
  targetHost: string
  targetPort: number
  credentials: NtlmCredentials
}

async function createNtlmTunnel(opts: TunnelOptions): Promise<tls.TLSSocket> {
  const { proxyHost, proxyPort, targetHost, targetPort, credentials } = opts
  consola.debug(
    `NTLM tunnel: connecting to proxy ${proxyHost}:${proxyPort} for ${targetHost}:${targetPort}`,
  )

  // Step 1: Connect to proxy and send Type 1 (negotiate) message
  let socket = await connectToProxy(proxyHost, proxyPort)
  const type1 = ntlm.createType1Message(
    credentials.workstation,
    credentials.domain,
  )
  consola.debug("NTLM tunnel: sending Type 1 negotiate message")
  sendConnect({ socket, host: targetHost, port: targetPort, authHeader: type1 })

  // Step 2: Read the 407 response with Type 2 challenge
  const response1 = await readHttpResponse(socket)
  consola.debug(`NTLM tunnel: proxy responded with ${response1.statusCode}`)

  if (response1.statusCode !== 407) {
    socket.destroy()
    if (response1.statusCode === 200) {
      // Proxy didn't require auth — shouldn't happen with NTLM but handle gracefully
      throw new Error(
        "Proxy accepted CONNECT without authentication — NTLM may not be required",
      )
    }
    throw new Error(
      `Proxy returned unexpected status ${response1.statusCode} during NTLM negotiate`,
    )
  }

  const proxyAuth = response1.headers["proxy-authenticate"]
  if (!proxyAuth) {
    socket.destroy()
    throw new Error(
      "Proxy returned 407 but no Proxy-Authenticate header — cannot proceed with NTLM",
    )
  }

  if (!/NTLM/i.test(proxyAuth)) {
    socket.destroy()
    if (/Negotiate/i.test(proxyAuth)) {
      throw new Error(
        "Proxy requires Kerberos/Negotiate authentication which is not supported — consider using a local NTLM bridge like Px or cntlm",
      )
    }
    throw new Error(`Proxy requires unsupported authentication: ${proxyAuth}`)
  }

  // Decode the Type 2 challenge
  const type2 = ntlm.decodeType2Message(proxyAuth)
  consola.debug(
    `NTLM tunnel: received Type 2 challenge (target: ${type2.targetName})`,
  )

  // Step 3: Some proxies close the socket after 407 — detect and reconnect
  const socketAlive = !socket.destroyed && socket.readable && socket.writable
  if (!socketAlive) {
    consola.debug("NTLM tunnel: proxy closed socket after 407 — reconnecting")
    socket = await connectToProxy(proxyHost, proxyPort)
  }

  // Send Type 3 (authenticate) message
  const type3 = ntlm.createType3Message(
    type2,
    credentials.username,
    credentials.password,
    credentials.workstation,
    credentials.domain,
  )
  consola.debug("NTLM tunnel: sending Type 3 authenticate message")
  sendConnect({ socket, host: targetHost, port: targetPort, authHeader: type3 })

  // Step 4: Read the final response
  const response2 = await readHttpResponse(socket)
  consola.debug(`NTLM tunnel: proxy responded with ${response2.statusCode}`)

  if (response2.statusCode === 407) {
    socket.destroy()
    throw new Error(
      "NTLM authentication rejected — check domain, username, and password",
    )
  }

  if (response2.statusCode !== 200) {
    socket.destroy()
    throw new Error(
      `Proxy returned unexpected status ${response2.statusCode} after NTLM authenticate`,
    )
  }

  consola.debug("NTLM tunnel: connection established, upgrading to TLS")

  // Step 5: Wrap the raw socket with TLS
  const tlsSocket = tls.connect({
    socket,
    servername: targetHost,
  })

  return new Promise((resolve, reject) => {
    tlsSocket.on("secureConnect", () => {
      consola.debug(`NTLM tunnel: TLS handshake complete for ${targetHost}`)
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
  credentials: NtlmCredentials
}

async function getOrCreateTunnel(
  pool: TunnelPool,
  targetHost: string,
  targetPort: number,
): Promise<TunnelEntry> {
  const key = `${targetHost}:${targetPort}`

  // Check cached tunnel
  const existing = pool.tunnels.get(key)
  if (existing && !existing.socket.destroyed) {
    return existing
  }
  pool.tunnels.delete(key)

  // Check if a handshake is already in progress
  const pendingEntry = pool.pending.get(key)
  if (pendingEntry) {
    return pendingEntry
  }

  // Start new handshake
  const promise = (async () => {
    try {
      const tlsSocket = await createNtlmTunnel({
        proxyHost: pool.proxyHost,
        proxyPort: pool.proxyPort,
        targetHost,
        targetPort,
        credentials: pool.credentials,
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
 * Create an undici dispatcher that routes requests through an NTLM-authenticating proxy.
 */
export function createNtlmDispatcher(
  proxyUrl: string,
  credentials: NtlmCredentials,
): {
  dispatch: Dispatcher["dispatch"]
  close: () => Promise<void>
  destroy: () => Promise<void>
} {
  const parsedProxy = new URL(proxyUrl)
  const pool: TunnelPool = {
    tunnels: new Map(),
    pending: new Map(),
    proxyHost: parsedProxy.hostname,
    proxyPort: Number.parseInt(parsedProxy.port || "8080", 10),
    credentials,
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
        consola.debug(`NTLM proxy bypass (non-HTTPS): ${origin.hostname}`)
        return (directAgent as unknown as Dispatcher).dispatch(options, handler)
      }

      const targetHost = origin.hostname
      const targetPort = Number.parseInt(origin.port || "443", 10)

      getOrCreateTunnel(pool, targetHost, targetPort)
        .then((entry) => {
          consola.debug(
            `NTLM proxy route: ${targetHost}:${targetPort} via ${pool.proxyHost}:${pool.proxyPort}`,
          )
          ;(entry.agent as unknown as Dispatcher).dispatch(options, handler)
        })
        .catch((err: unknown) => {
          pool.tunnels.delete(`${targetHost}:${targetPort}`)
          const error = err instanceof Error ? err : new Error(String(err))
          consola.error(`NTLM proxy error for ${targetHost}: ${error.message}`)
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
