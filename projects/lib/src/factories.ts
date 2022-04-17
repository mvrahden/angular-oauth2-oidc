import { MemoryStorage } from './types'

export const createDefaultLogger = () => console

export const createDefaultStorage = () =>
  typeof sessionStorage !== 'undefined' ? sessionStorage : new MemoryStorage()
