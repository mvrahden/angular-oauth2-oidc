import { Injectable } from '@angular/core'

export abstract class DateTimeProvider {
  public abstract now(): number
  public abstract new(): Date
}

@Injectable()
export class SystemDateTimeProvider extends DateTimeProvider {
  public now(): number {
    return Date.now()
  }

  public new(): Date {
    return new Date()
  }
}
