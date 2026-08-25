import { ApplicationConfig, provideZoneChangeDetection, APP_INITIALIZER } from '@angular/core';
import { SecureShieldService } from './services/secureshield.service';

export function initializeSecureShield(shieldService: SecureShieldService) {
  return () => shieldService.initSecureShield();
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    {
      provide: APP_INITIALIZER,
      useFactory: initializeSecureShield,
      deps: [SecureShieldService],
      multi: true
    }
  ],
};
