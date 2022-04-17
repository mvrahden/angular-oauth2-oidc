// see: https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#The_.22Unicode_Problem.22
export const b64DecodeUnicode = (base64: string) => Buffer.from(base64, 'base64url').toString('utf8')

export const base64UrlEncode = (str: string): string => Buffer.from(str).toString('base64url')
