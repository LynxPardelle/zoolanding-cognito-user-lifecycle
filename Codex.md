# Codex Agent Memory

This repository owns the Zoolanding Cognito user lifecycle trigger.

## Durable Rules

- Keep this Lambda separate from `zoolanding-api-proxy`; the API proxy handles browser-initiated custom auth endpoints, while this trigger repairs Cognito-side lifecycle events.
- `PROFILE_CONFIG_JSON` is non-secret server-side deployment config. It may include user pool IDs, public app client IDs, tenant IDs, tenant claim names, allowed groups, and default groups. It must not include secrets, tokens, passwords, credential refs, private keys, or raw OAuth client secrets.
- Never trust Cognito `clientMetadata` for tenant or group assignment. The handler matches only `userPoolId` plus `callerContext.clientId`, then derives tenant and groups from the server-side profile.
- Supported trigger events must fail closed when no server-side profile matches. A missing profile is a deployment/configuration error, not a safe no-op.
- Use `PostConfirmation_ConfirmSignUp` / `PostConfirmation_AdminConfirmSignUp` for self-signup assignment. `PostConfirmation_ConfirmForgotPassword` must not change authorization state.
- `PostAuthentication_Authentication` can repair users created outside self-signup when `repairOnPostAuthentication` is true, but AWS documents that post-authentication profile adjustments are reflected on the next sign-in. Do not rely on it for the token already being issued in that same sign-in.
- `dev`, `test`, and `main` are the service branches. `test` and `main` should be protected with required `guard` and `test` checks; deployments use GitHub Environments `dev`, `test`, and `production`.
