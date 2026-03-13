import {
  createType1Message,
  createType3Message,
  extractNtlmMessageFromAuthenticateHeader,
  parseType2Message,
} from "@node-ntlm/core"
import { describe, test, expect, afterAll, beforeAll } from "bun:test"
import net from "node:net"

// ---- Unit tests for NTLM message construction ----

describe("@node-ntlm/core message construction", () => {
  test("createType1Message returns NTLM prefixed base64 string", () => {
    const msg = createType1Message({
      domain: "DOMAIN",
      workstation: "WORKSTATION",
    })
    expect(msg).toMatch(/^NTLM [A-Za-z0-9+/=]+$/)
  })

  test("createType1Message works with empty strings", () => {
    const msg = createType1Message({ domain: "", workstation: "" })
    expect(msg).toMatch(/^NTLM [A-Za-z0-9+/=]+$/)
  })

  test("parseType2Message parses a valid Type 2 message", () => {
    const buf = Buffer.alloc(56)
    buf.write("NTLMSSP\0", 0, 8, "ascii")
    buf.writeUInt32LE(2, 8)
    buf.writeUInt16LE(0, 12)
    buf.writeUInt16LE(0, 14)
    buf.writeUInt32LE(0, 16)
    buf.writeUInt32LE(0x00000202, 20)
    buf.write("ABCDEFGH", 24, 8, "ascii")

    // parseType2Message expects "NTLM <base64>" format
    const decoded = parseType2Message(`NTLM ${buf.toString("base64")}`)

    expect(decoded).toBeDefined()
    expect(decoded.serverChallenge).toBeInstanceOf(Buffer)
    expect(decoded.serverChallenge.length).toBe(8)
  })

  test("extractNtlmMessageFromAuthenticateHeader extracts token", () => {
    const header =
      "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
    const token = extractNtlmMessageFromAuthenticateHeader(header)
    expect(token).toBeDefined()
    // Returns the full "NTLM <base64>" string, not just the base64 part
    expect(token).toBe(
      "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
    )
  })

  test("extractNtlmMessageFromAuthenticateHeader returns undefined for non-NTLM", () => {
    expect(
      extractNtlmMessageFromAuthenticateHeader("Basic realm=test"),
    ).toBeUndefined()
    expect(extractNtlmMessageFromAuthenticateHeader(null)).toBeUndefined()
  })

  test("createType3Message returns NTLM prefixed base64 string", () => {
    const buf = Buffer.alloc(56)
    buf.write("NTLMSSP\0", 0, 8, "ascii")
    buf.writeUInt32LE(2, 8)
    buf.writeUInt16LE(0, 12)
    buf.writeUInt16LE(0, 14)
    buf.writeUInt32LE(0, 16)
    buf.writeUInt32LE(0x00000202, 20)
    buf.write("ABCDEFGH", 24, 8, "ascii")

    const type2 = parseType2Message(`NTLM ${buf.toString("base64")}`)
    const type3 = createType3Message(type2, {
      domain: "DOMAIN",
      workstation: "WORKSTATION",
      username: "testuser",
      password: "testpass",
    })

    expect(type3).toMatch(/^NTLM [A-Za-z0-9+/=]+$/)
  })

  test("createType3Message handles missing targetInfo gracefully", () => {
    // Build Type 2 without NegotiateTargetInfo flag
    const buf = Buffer.alloc(56)
    buf.write("NTLMSSP\0", 0, 8, "ascii")
    buf.writeUInt32LE(2, 8)
    buf.writeUInt16LE(0, 12)
    buf.writeUInt16LE(0, 14)
    buf.writeUInt32LE(0, 16)
    // Flags WITHOUT NegotiateTargetInfo (0x00800000)
    buf.writeUInt32LE(0x00000202, 20)
    buf.write("ABCDEFGH", 24, 8, "ascii")

    const type2 = parseType2Message(`NTLM ${buf.toString("base64")}`)
    expect(type2.targetInfo).toBeUndefined()

    // This should NOT throw (the old ntlm-client crashed here)
    const type3 = createType3Message(type2, {
      domain: "DOMAIN",
      workstation: "WORKSTATION",
      username: "testuser",
      password: "testpass",
    })

    expect(type3).toMatch(/^NTLM [A-Za-z0-9+/=]+$/)
  })
})

// ---- Integration test with mock NTLM proxy server ----

describe("NTLM proxy handshake with mock server", () => {
  let mockServer: net.Server
  let serverPort: number
  const handshakeLog: Array<string> = []

  beforeAll(async () => {
    mockServer = net.createServer((socket) => {
      let step = 0
      let buffer = ""

      socket.on("data", (data) => {
        buffer += data.toString("ascii")

        if (!buffer.includes("\r\n\r\n")) return

        const request = buffer
        buffer = ""

        if (step === 0) {
          const hasNtlm = /Proxy-Authorization: NTLM /i.test(request)
          handshakeLog.push(hasNtlm ? "type1-received" : "no-ntlm-header")

          if (!hasNtlm) {
            socket.write(
              "HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: NTLM\r\n\r\n",
            )
            return
          }

          const challengeBuf = Buffer.alloc(56)
          challengeBuf.write("NTLMSSP\0", 0, 8, "ascii")
          challengeBuf.writeUInt32LE(2, 8)
          challengeBuf.writeUInt16LE(0, 12)
          challengeBuf.writeUInt16LE(0, 14)
          challengeBuf.writeUInt32LE(0, 16)
          challengeBuf.writeUInt32LE(0x00000202, 20)
          challengeBuf.write("CHALLENG", 24, 8, "ascii")

          const challenge = challengeBuf.toString("base64")
          socket.write(
            `HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: NTLM ${challenge}\r\nContent-Length: 0\r\n\r\n`,
          )
          step = 1
          handshakeLog.push("type2-sent")
        } else if (step === 1) {
          const type3Match = /Proxy-Authorization: NTLM ([A-Z0-9+/=]+)/i.exec(
            request,
          )
          if (type3Match) {
            handshakeLog.push("type3-received")

            const msgBuf = Buffer.from(type3Match[1], "base64")
            const sig = msgBuf.subarray(0, 8).toString("ascii")
            const msgType = msgBuf.readUInt32LE(8)

            if (sig === "NTLMSSP\0" && msgType === 3) {
              handshakeLog.push("type3-valid")
              socket.write("HTTP/1.1 200 Connection established\r\n\r\n")
              handshakeLog.push("tunnel-established")
            } else {
              handshakeLog.push("type3-invalid")
              socket.write("HTTP/1.1 407 Auth Failed\r\n\r\n")
            }
          } else {
            handshakeLog.push("no-type3")
            socket.write("HTTP/1.1 407 Auth Failed\r\n\r\n")
          }
          step = 2
        }
      })
    })

    await new Promise<void>((resolve) => {
      mockServer.listen(0, "127.0.0.1", () => {
        const addr = mockServer.address() as net.AddressInfo
        serverPort = addr.port
        resolve()
      })
    })
  })

  afterAll(() => {
    mockServer.close()
  })

  test("performs full NTLM handshake against mock proxy", async () => {
    const socket = net.createConnection(serverPort, "127.0.0.1")

    await new Promise<void>((resolve) => socket.on("connect", resolve))

    // Send Type 1
    const type1 = createType1Message({
      domain: "DOMAIN",
      workstation: "WORKSTATION",
    })
    socket.write(
      `CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: ${type1}\r\n\r\n`,
    )

    // Read Type 2 response
    const response1 = await new Promise<string>((resolve) => {
      socket.once("data", (data) => resolve(data.toString("ascii")))
    })

    expect(response1).toContain("407")
    expect(response1).toContain("Proxy-Authenticate: NTLM")

    // Extract Proxy-Authenticate header value from raw HTTP response
    const authHeaderMatch = /Proxy-Authenticate: (.+)\r\n/i.exec(response1)
    expect(authHeaderMatch).not.toBeNull()

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const authHeader = authHeaderMatch![1]
    const ntlmToken = extractNtlmMessageFromAuthenticateHeader(authHeader)
    expect(ntlmToken).toBeDefined()

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const type2 = parseType2Message(ntlmToken!)
    expect(type2).toBeDefined()
    expect(type2.serverChallenge).toBeInstanceOf(Buffer)

    // Send Type 3
    const type3 = createType3Message(type2, {
      domain: "DOMAIN",
      workstation: "WORKSTATION",
      username: "testuser",
      password: "testpass",
    })
    socket.write(
      `CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: ${type3}\r\n\r\n`,
    )

    // Read final response
    const response2 = await new Promise<string>((resolve) => {
      socket.once("data", (data) => resolve(data.toString("ascii")))
    })

    expect(response2).toContain("200")
    socket.destroy()

    // Verify handshake sequence
    expect(handshakeLog).toContain("type1-received")
    expect(handshakeLog).toContain("type2-sent")
    expect(handshakeLog).toContain("type3-received")
    expect(handshakeLog).toContain("type3-valid")
    expect(handshakeLog).toContain("tunnel-established")
  })
})
