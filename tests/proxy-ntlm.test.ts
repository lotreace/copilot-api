import { describe, test, expect, afterAll, beforeAll } from "bun:test"
import net from "node:net"
import ntlm from "ntlm-client"

// ---- Unit tests for NTLM message construction ----

describe("ntlm-client message construction", () => {
  test("createType1Message returns NTLM prefixed base64 string", () => {
    const msg = ntlm.createType1Message("WORKSTATION", "DOMAIN")
    expect(msg).toMatch(/^NTLM [A-Za-z0-9+/=]+$/)
  })

  test("createType1Message works without arguments", () => {
    const msg = ntlm.createType1Message()
    expect(msg).toMatch(/^NTLM [A-Za-z0-9+/=]+$/)
  })

  test("decodeType2Message parses a valid Type 2 message", () => {
    // Create a minimal valid Type 2 message
    // NTLMSSP signature + type 2 + minimal fields
    const buf = Buffer.alloc(56)
    buf.write("NTLMSSP\0", 0, 8, "ascii") // signature
    buf.writeUInt32LE(2, 8) // message type
    // Target name: empty
    buf.writeUInt16LE(0, 12) // target name length
    buf.writeUInt16LE(0, 14) // target name max length
    buf.writeUInt32LE(0, 16) // target name offset
    // Flags: NTLM key + OEM
    buf.writeUInt32LE(0x00000202, 20)
    // Challenge (8 bytes at offset 24)
    buf.write("ABCDEFGH", 24, 8, "ascii")

    const base64 = buf.toString("base64")
    const decoded = ntlm.decodeType2Message(`NTLM ${base64}`)

    expect(decoded).toBeDefined()
    expect(decoded.challenge).toBeInstanceOf(Buffer)
    expect(decoded.challenge.length).toBe(8)
  })

  test("decodeType2Message throws on invalid input", () => {
    expect(() => ntlm.decodeType2Message("NTLM invalid===")).toThrow()
  })

  test("createType3Message returns NTLM prefixed base64 string", () => {
    // Build a minimal Type 2 to feed into Type 3
    const buf = Buffer.alloc(56)
    buf.write("NTLMSSP\0", 0, 8, "ascii")
    buf.writeUInt32LE(2, 8)
    buf.writeUInt16LE(0, 12)
    buf.writeUInt16LE(0, 14)
    buf.writeUInt32LE(0, 16)
    buf.writeUInt32LE(0x00000202, 20)
    buf.write("ABCDEFGH", 24, 8, "ascii")

    const type2 = ntlm.decodeType2Message(`NTLM ${buf.toString("base64")}`)
    const type3 = ntlm.createType3Message(
      type2,
      "testuser",
      "testpass",
      "WORKSTATION",
      "DOMAIN",
    )

    expect(type3).toMatch(/^NTLM [A-Za-z0-9+/=]+$/)
  })
})

// ---- Integration test with mock NTLM proxy server ----

describe("NTLM proxy handshake with mock server", () => {
  let mockServer: net.Server
  let serverPort: number
  const handshakeLog: Array<string> = []

  beforeAll(async () => {
    // Create a mock proxy that implements the NTLM CONNECT handshake
    mockServer = net.createServer((socket) => {
      let step = 0
      let buffer = ""

      socket.on("data", (data) => {
        buffer += data.toString("ascii")

        // Wait for complete HTTP request (headers end with \r\n\r\n)
        if (!buffer.includes("\r\n\r\n")) return

        const request = buffer
        buffer = ""

        if (step === 0) {
          // Step 1: Expect CONNECT with Type 1 NTLM message
          const hasNtlm = /Proxy-Authorization: NTLM /i.test(request)
          handshakeLog.push(hasNtlm ? "type1-received" : "no-ntlm-header")

          if (!hasNtlm) {
            socket.write(
              "HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: NTLM\r\n\r\n",
            )
            return
          }

          // Build a Type 2 challenge response
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
          // Step 2: Expect CONNECT with Type 3 NTLM message
          const type3Match = /Proxy-Authorization: NTLM ([A-Z0-9+/=]+)/i.exec(
            request,
          )
          if (type3Match) {
            handshakeLog.push("type3-received")

            // Verify it's a valid NTLM Type 3 message
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

    // Start listening on a random port
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
    const type1 = ntlm.createType1Message("WORKSTATION", "DOMAIN")
    socket.write(
      `CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: ${type1}\r\n\r\n`,
    )

    // Read Type 2 response
    const response1 = await new Promise<string>((resolve) => {
      socket.once("data", (data) => resolve(data.toString("ascii")))
    })

    expect(response1).toContain("407")
    expect(response1).toContain("Proxy-Authenticate: NTLM")

    // Extract and decode Type 2
    const ntlmMatch = /NTLM ([A-Z0-9+/=]+)/i.exec(response1)
    expect(ntlmMatch).not.toBeNull()

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const type2 = ntlm.decodeType2Message(`NTLM ${ntlmMatch![1]}`)
    expect(type2).toBeDefined()
    expect(type2.challenge).toBeInstanceOf(Buffer)

    // Send Type 3
    const type3 = ntlm.createType3Message(
      type2,
      "testuser",
      "testpass",
      "WORKSTATION",
      "DOMAIN",
    )
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
