import { Observable, of } from 'rxjs'
import { ValidationHandler, ValidationParams } from './validation-handler'

/**
 * A validation handler that isn't validating nothing.
 * Can be used to skip validation (at your own risk).
 */
export class NullValidationHandler implements ValidationHandler {
  validateSignature(validationParams: ValidationParams): Observable<any> {
    return of(null)
  }
  validateAtHash(validationParams: ValidationParams): Observable<boolean> {
    return of(true)
  }
}
