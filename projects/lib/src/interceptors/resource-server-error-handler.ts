import { HttpResponse } from '@angular/common/http'
import { Observable, throwError } from 'rxjs'

export abstract class OAuthResourceServerErrorHandler {
  public abstract handleError(err: HttpResponse<any>): Observable<any>
}

export class OAuthNoopResourceServerErrorHandler implements OAuthResourceServerErrorHandler {
  public handleError(err: HttpResponse<any>): Observable<any> {
    return throwError(err)
  }
}
