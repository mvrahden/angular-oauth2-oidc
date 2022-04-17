import { Injectable } from '@angular/core'

@Injectable()
export class UrlHelperService {
  public getHashFragmentParams(customHashFragment?: string): object {
    let hash = customHashFragment || window.location.hash

    hash = decodeURIComponent(hash)

    if (hash.indexOf('#') !== 0) {
      return {}
    }

    const questionMarkPosition = hash.indexOf('?')

    if (questionMarkPosition > -1) {
      hash = hash.substr(questionMarkPosition + 1)
    } else {
      hash = hash.substr(1)
    }

    return this.parseQueryString(hash)
  }

  public parseQueryString(queryString: string): object {
    if (!queryString) {
      return {}
    }

    return queryString.split('&').reduce((data: object, pair) => {
      let escapedKey: string
      let escapedValue: string

      const separatorIndex = pair.indexOf('=')

      if (separatorIndex === -1) {
        escapedKey = pair
        escapedValue = null
      } else {
        escapedKey = pair.substr(0, separatorIndex)
        escapedValue = pair.substr(separatorIndex + 1)
      }

      let key = decodeURIComponent(escapedKey)
      const value = decodeURIComponent(escapedValue)

      if (key.substr(0, 1) === '/') {
        key = key.substr(1)
      }

      data[key] = value
      return { ...data }
    }, {})
  }
}
