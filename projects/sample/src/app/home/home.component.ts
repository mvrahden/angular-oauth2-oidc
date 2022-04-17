import { authConfig } from '../auth.config'
import { Component, OnInit } from '@angular/core'
import { OAuthService, UserInfo } from 'angular-oauth2-oidc'
import { authCodeFlowConfig } from '../auth-code-flow.config'
import { ActivatedRoute } from '@angular/router'
import { catchError, map, mergeMap } from 'rxjs/operators'
import { Observable } from 'rxjs'

@Component({
  templateUrl: './home.component.html',
})
export class HomeComponent implements OnInit {
  loginFailed: boolean = false
  userProfile: object
  usePopup: boolean
  login: false

  constructor(private route: ActivatedRoute, private oauthService: OAuthService) {}

  get hasValidAccessToken() {
    return this.oauthService.hasValidAccessToken()
  }

  get hasValidIdToken() {
    return this.oauthService.hasValidIdToken()
  }

  ngOnInit() {
    this.route.params.subscribe((p) => {
      this.login = p['login']
    })

    // This would directly (w/o user interaction) redirect the user to the
    // login page if they are not already logged in.
    /*
        this.oauthService.loadDiscoveryDocumentAndTryLogin().then(_ => {
            if (!this.oauthService.hasValidIdToken() || !this.oauthService.hasValidAccessToken()) {
              this.oauthService.initImplicitFlow('some-state');
            }
        });
    */
  }

  loginImplicit() {
    // Tweak config for implicit flow
    this.oauthService.configure(authConfig)
    this.oauthService.loadDiscoveryDocument().subscribe({
      next: doc => console.log('success', doc),
      error: err => console.error('failed', err)
    })
    sessionStorage.setItem('flow', 'implicit')

    this.oauthService.initLoginFlow('/some-state;p1=1;p2=2?p3=3&p4=4')
    // the parameter here is optional. It's passed around and can be used after logging in
  }

  loginImplicitInPopup() {
    // Tweak config for implicit flow
    this.oauthService.configure(authConfig)
    this.oauthService.loadDiscoveryDocument().subscribe({
      next: doc => console.log('success', doc),
      error: err => console.error('failed', err)
    })
    sessionStorage.setItem('flow', 'implicit')

    this.oauthService
      .initLoginFlowInPopup()
      .pipe(mergeMap(() => this.loadUserProfile()))
      .subscribe({
        next: userInfo => {
          this.userProfile = userInfo
          console.log('success', userInfo)
        },
        error: err => console.error('failed', err),
      })
    // the parameter here is optional. It's passed around and can be used after logging in
  }

  loginCode() {
    // Tweak config for code flow
    this.oauthService.configure(authCodeFlowConfig)
    this.oauthService.loadDiscoveryDocument().subscribe({
      next: doc => console.log('success', doc),
      error: err => console.error('failed', err)
    })
    sessionStorage.setItem('flow', 'code')

    this.oauthService.initLoginFlow('/some-state;p1=1;p2=2?p3=3&p4=4')
    // the parameter here is optional. It's passed around and can be used after logging in
  }

  loginCodeInPopup() {
    // Tweak config for code flow
    this.oauthService.configure(authCodeFlowConfig)
    this.oauthService.loadDiscoveryDocument().subscribe({
      next: doc => console.log('success', doc),
      error: err => console.error('failed', err)
    })
    sessionStorage.setItem('flow', 'code')

    this.oauthService
      .initLoginFlowInPopup()
      .pipe(mergeMap(() => this.loadUserProfile()))
      .subscribe({
        next: userInfo => {
          this.userProfile = userInfo
          console.log('success', userInfo)
        },
        error: err => console.error('failed', err),
      })
  }

  logout() {
    // this.oauthService.logOut();
    this.oauthService.revokeTokenAndLogout().subscribe({
      next: ok => console.log('logged out', ok),
      error: err => console.error('failed', err),
    })
  }

  loadUserProfile(): Observable<UserInfo> {
    return this.oauthService.loadUserProfile()
  }

  startAutomaticRefresh(): void {
    this.oauthService.setupAutomaticSilentRefresh()
  }

  stopAutomaticRefresh(): void {
    this.oauthService.stopAutomaticRefresh()
  }

  get givenName() {
    var claims = this.oauthService.getIdentityClaims()
    if (!claims) return null
    return claims['given_name']
  }

  get familyName() {
    var claims = this.oauthService.getIdentityClaims()
    if (!claims) return null
    return claims['family_name']
  }

  refresh() {
    this.oauthService.config.oidc = true

    if (!this.oauthService.config.useSilentRefresh && this.oauthService.config.responseType === 'code') {
      this.oauthService
        .refreshToken().subscribe({
        next: token => console.log('refresh success', token),
        error: err => console.error('refresh failed', err),
      })
    } else {
      this.oauthService
        .silentRefresh().subscribe({
        next: token => console.log('silent refresh success', token),
        error: err => console.error('silent refresh failed', err),
      })
    }
  }

  set requestAccessToken(value: boolean) {
    this.oauthService.config.requestAccessToken = value
    localStorage.setItem('requestAccessToken', '' + value)
  }

  get requestAccessToken() {
    return this.oauthService.config.requestAccessToken
  }

  set useHashLocationStrategy(value: boolean) {
    const oldValue = localStorage.getItem('useHashLocationStrategy') === 'true'
    if (value !== oldValue) {
      localStorage.setItem('useHashLocationStrategy', value ? 'true' : 'false')
      window.location.reload()
    }
  }

  get useHashLocationStrategy() {
    return localStorage.getItem('useHashLocationStrategy') === 'true'
  }

  get id_token() {
    return this.oauthService.getIdToken()
  }

  get access_token() {
    return this.oauthService.getAccessToken()
  }

  get id_token_expiration() {
    return this.oauthService.getIdTokenExpiration()
  }

  get access_token_expiration() {
    return this.oauthService.getAccessTokenExpiration()
  }
}
