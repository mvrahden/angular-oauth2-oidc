import { Routes, RouterModule } from '@angular/router'
import { FlightSearchReactiveComponent } from './flight-search-reactive/flight-search-reactive.component'
import { PassengerSearchComponent } from './passenger-search/passenger-search.component'
import { FlightEditComponent } from './flight-edit/flight-edit.component'
import { FlightBookingComponent } from './flight-booking.component'
import { AuthGuard } from '../shared/auth/auth.guard'
import { LeaveComponentGuard } from '../shared/deactivation/LeaveComponentGuard'

let FLIGHT_BOOKING_ROUTES: Routes = [
  {
    path: '',
    component: FlightBookingComponent,
    canActivate: [AuthGuard],
    children: [
      {
        path: 'flight-search',
        component: FlightSearchReactiveComponent,
      },
      {
        path: 'passenger-search',
        component: PassengerSearchComponent,
      },
      {
        path: 'flight-edit/:id',
        component: FlightEditComponent,
        canDeactivate: [LeaveComponentGuard],
      },
    ],
  },
]

export let FlightBookingRouterModule = RouterModule.forChild(FLIGHT_BOOKING_ROUTES)
