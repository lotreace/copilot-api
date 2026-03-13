declare module "ntlm-client" {
  interface Type2Message {
    flags: number
    encoding: string
    version: number
    challenge: Buffer
    targetName: string
    targetInfo: Record<string, string>
  }

  export function createType1Message(
    workstation?: string,
    target?: string,
  ): string

  export function decodeType2Message(str: string): Type2Message

  // eslint-disable-next-line max-params
  export function createType3Message(
    type2Message: Type2Message,
    username: string,
    password: string,
    workstation?: string,
    target?: string,
  ): string
}
