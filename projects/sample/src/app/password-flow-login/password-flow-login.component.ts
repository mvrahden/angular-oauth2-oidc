import { authPasswordFlowConfig } from '../auth-password-flow.config'
import { OAuthService } from 'angular-oauth2-oidc'
import { Component, OnInit } from '@angular/core'

@Component({
  selector: 'app-password-flow-login',
  templateUrl: './password-flow-login.component.html',
})
export class PasswordFlowLoginComponent implements OnInit {
  userName: string
  password: string
  loginFailed: boolean = false
  userProfile: object

  constructor(private oauthService: OAuthService) {
    // Tweak config for password flow
    // This is just needed b/c this demo uses both,
    // implicit flow as well as password flow

    this.oauthService.configure(authPasswordFlowConfig)
    this.oauthService.loadDiscoveryDocument()
  }

  ngOnInit() {}

  loadUserProfile(): void {
    this.oauthService.loadUserProfile().subscribe((up) => (this.userProfile = up))
  }

  get access_token() {
    return this.oauthService.getAccessToken()
  }

  get access_token_expiration() {
    return this.oauthService.getAccessTokenExpiration()
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

  loginWithPassword() {
    this.oauthService
      .fetchTokenUsingPasswordFlowAndLoadUserProfile(this.userName, this.password)
      .subscribe({
        next: doc => {
          console.log('login success', doc)
          this.loginFailed = false
        },
        error: (err) => {
          console.error('login failed', err)
          this.loginFailed = true
        },
      })
  }

  logout() {
    this.oauthService.logOut(true)
  }
}
