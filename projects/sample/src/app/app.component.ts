import { noDiscoveryAuthConfig } from './auth-no-discovery.config'
import { authConfig } from './auth.config'
import { Component } from '@angular/core'
import { OAuthService, NullValidationHandler } from 'angular-oauth2-oidc'
import { Router } from '@angular/router'
import { filter, map, tap } from 'rxjs/operators'
import { authCodeFlowConfig } from './auth-code-flow.config'
import { useHash } from '../flags'

@Component({
  selector: 'flight-app',
  templateUrl: './app.component.html',
})
export class AppComponent {
  constructor(private router: Router, private oauthService: OAuthService) {
    // Remember the selected configuration
    if (sessionStorage.getItem('flow') === 'code') {
      this.configureCodeFlow()
    } else {
      this.configureImplicitFlow()
    }

    // Automatically load user profile
    this.oauthService.events.pipe(filter((e) => e.type === 'token_received')).subscribe((_) => {
      console.debug('state', this.oauthService.state)
      this.oauthService.loadUserProfile()

      const scopes = this.oauthService.getGrantedScopes()
      console.debug('scopes', scopes)
    })
  }

  private configureCodeFlow() {
    this.oauthService.configure(authCodeFlowConfig)
    this.oauthService.loadDiscoveryDocumentAndTryLogin().pipe(
      map((_) => {
        if (useHash) {
          this.router.navigate(['/'])
        }
      })
    )

    // Optional
    this.oauthService.setupAutomaticSilentRefresh()
  }

  private configureImplicitFlow() {
    this.oauthService.configure(authConfig)
    // this.oauthService.tokenValidationHandler = new JwksValidationHandler()

    this.oauthService.loadDiscoveryDocumentAndTryLogin().pipe(
      map((ok) => {
        if (ok && useHash) {
          this.router.navigate(['/'])
        }
      })
    )

    // Optional
    this.oauthService.setupAutomaticSilentRefresh()

    // Display all events
    this.oauthService.events.subscribe((e) => {
      console.debug('oauth/oidc event', e)
    })

    this.oauthService.events.pipe(filter((e) => e.type === 'session_terminated')).subscribe((e) => {
      console.debug('Your session has been terminated!')
    })
  }

  //
  // Below you find further examples for configuration functions
  //

  private configureWithoutDiscovery() {
    this.oauthService.configure(noDiscoveryAuthConfig)
    this.oauthService.setTokenValidationHandler(new NullValidationHandler())
    this.oauthService.tryLogin().subscribe((ok) => console.log(`logged in`, ok))
  }

  private configureAuth() {
    //
    // This method demonstrated the old API; see configureWithNewConfigApi for new one
    //
    this.oauthService.configure({
      // URL of the SPA to redirect the user to after login
      redirectUri: window.location.origin + '/index.html',
      // URL of the SPA to redirect the user after silent refresh
      silentRefreshRedirectUri: window.location.origin + '/silent-refresh.html',
      // The SPA's id. The SPA is registerd with this id at the auth-server
      clientId: 'spa-demo',
      // set the scope for the permissions the client should request
      // The first three are defined by OIDC. The 4th is a usecase-specific one
      scope: 'openid profile email voucher',
      // Url of the Identity Provider
      issuer: 'https://steyer-identity-server.azurewebsites.net/identity',
      // Set a dummy secret for PasswordFlow
      // Please note that the auth-server used here demand the client to transmit a client secret, although
      // the standard explicitly cites that the password flow can also be used without it. Using a client secret
      // does not make sense for a SPA that runs in the browser. That's why the property is called dummyClientSecret
      // Using such a dummy secreat is as safe as using no secret.
      dummyClientSecret: 'geheim',
    })

    this.oauthService.setTokenValidationHandler(new NullValidationHandler())

    this.oauthService.events.subscribe((e) => {
      console.debug('oauth/oidc event', e)
    })

    // Load Discovery Document and then try to login the user
    this.oauthService
      .loadDiscoveryDocument()
      .pipe(
        tap((doc) => console.log(`got doc`, doc)),
        map((doc) => {
          this.oauthService.tryLogin()
        })
      )
      .subscribe(() => {})

    this.oauthService.events.pipe(filter((e) => e.type === 'token_expires')).subscribe((e) => {
      console.debug('received token_expires event', e)
      this.oauthService.silentRefresh()
    })
  }
}
