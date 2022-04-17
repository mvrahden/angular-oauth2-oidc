import { HttpParameterCodec } from '@angular/common/http'
/**
 * This custom encoder allows charactes like +, % and / to be used in passwords
 */
export class WebHttpUrlEncodingCodec implements HttpParameterCodec {
  public encodeKey(k: string): string {
    return encodeURIComponent(k)
  }

  public encodeValue(v: string): string {
    return encodeURIComponent(v)
  }

  public decodeKey(k: string): string {
    return decodeURIComponent(k)
  }

  public decodeValue(v: string) {
    return decodeURIComponent(v)
  }
}
