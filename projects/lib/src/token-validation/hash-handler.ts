import { Injectable } from '@angular/core'

import fsha256 from 'fast-sha256'

/**
 * Abstraction for crypto algorithms
 */
export abstract class HashHandler {
  public abstract toSha256(valueToHash: string): string
}

@Injectable()
export class DefaultHashHandler implements HashHandler {
  toSha256(valueToHash: string): string {
    return DefaultHashHandler.encodeUTF8(
      fsha256(DefaultHashHandler.decodeUTF8(valueToHash))
    )
  }

  private static decodeUTF8(s) {
    if (typeof s !== 'string') throw new TypeError('expected string')
    let i: number
    const d = s
    const b = new Uint8Array(d.length)
    for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i)
    return b
  }

  private static encodeUTF8(arr) {
    let i: number
    const s = []
    for (i = 0; i < arr.length; i++) s.push(String.fromCharCode(arr[i]))
    return s.join('')
  }

  toHashString2(byteArray: number[]) {
    let result = ''
    for (let e of byteArray) {
      result += String.fromCharCode(e)
    }
    return result
  }

  toHashString(buffer: ArrayBuffer) {
    const byteArray = new Uint8Array(buffer)
    let result = ''
    for (let e of byteArray) {
      result += String.fromCharCode(e)
    }
    return result
  }
}
