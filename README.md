# Zoolanding Cognito User Lifecycle

Serverless Cognito trigger for generic draft auth.

It assigns server-approved custom attributes and default groups to Cognito users without trusting browser payloads or Cognito `clientMetadata`.

## Why This Exists

`zoolanding-api-proxy` already handles custom auth forms. Its `/auth/signup` endpoint sets `custom:tenant_id` and approved default groups from the private auth profile. This repository covers the other path: users who are confirmed directly by Cognito flows such as Managed Login/self-signup, plus optional repair for users created outside the custom signup endpoint.

AWS behavior to account for:

- `PostConfirmation` can run after self-signup confirmation and can call AWS APIs to populate attributes.
- AWS documents that `PostConfirmation` does not run for users created with administrator credentials.
- `PostAuthentication` runs after authentication completes and before token delivery, but profile adjustments are reflected on the next sign-in. Use it as repair, not as the primary first-token authorization guarantee.

## Profile Config

Deployment supplies the profile config per environment. It is server-side, non-secret config. Use `PROFILE_CONFIG_JSON_BASE64` for deployments so raw JSON cannot be split by shell argument parsing. `PROFILE_CONFIG_JSON` remains supported only as a local/backward-compatible fallback.

```json
{
  "version": 1,
  "profiles": [
    {
      "enabled": true,
      "environment": "prod",
      "domain": "zoositioweb.com.mx",
      "authProfileId": "staff",
      "userPoolId": "us-east-1_Pq5OCadbK",
      "clientIds": ["16jb6ml9q5jdh6blj7f668fajp"],
      "tenantId": "zoosite",
      "tenantClaim": "custom:tenant_id",
      "attributes": {
        "custom:tenant_id": "zoosite"
      },
      "allowedGroups": ["zoosite-client", "zoosite-admin"],
      "defaultGroups": ["zoosite-client"],
      "groupAssignmentMode": "ifNoAllowedGroup",
      "repairOnPostAuthentication": true
    }
  ]
}
```

Rules:

- `defaultGroups` must be a subset of `allowedGroups`.
- `clientIds` must contain at least one public app client ID.
- `attributes` may contain server-owned custom Cognito attributes such as `custom:tenant_id`, `custom:plan_id`, or `custom:dashboard_scope`.
- `tenantId` and `tenantClaim` remain supported as the standard tenant shortcut; if `attributes` also includes the tenant claim, it must match `tenantId`.
- `groupAssignmentMode: "always"` adds default groups every time Cognito invokes the trigger. `groupAssignmentMode: "ifNoAllowedGroup"` first checks current groups and adds defaults only when the user has none of the allowed groups.
- Supported trigger events fail closed when no profile matches `userPoolId` and `callerContext.clientId`.
- Secret-looking keys and values are rejected before any Cognito call.
- Client metadata is ignored for tenant and group assignment.

## Local Verification

```powershell
python -m unittest discover -s tests -p "test_*.py"
sam validate
```

Optional audit:

```powershell
pip-audit -r requirements.txt
```

## Deployment Shape

Branches:

- `dev` deploys to GitHub Environment `dev` and SAM config `dev`.
- `test` deploys to GitHub Environment `test` and SAM config `test`.
- `main` deploys to GitHub Environment `production` and SAM config `prod`.

Required GitHub Environment variables:

- `AWS_ROLE_ARN`
- `AWS_REGION`, normally `us-east-1`
- `PROFILE_CONFIG_JSON_BASE64`, base64-encoded compact JSON. The workflow validates it, normalizes it, and passes only `ProfileConfigJsonBase64` to SAM.

After deployment, attach the output `FunctionArn` to the Cognito user pool triggers:

- Post confirmation
- Post authentication, only when repair for admin-created or legacy users is desired

Trigger attachment is an AWS mutation and should be performed only after review of the target environment and profile JSON.

## Security Model

- No public API Gateway route is created.
- The Lambda can only read groups, update user attributes, and add users to groups in Cognito user pools in the same AWS account and region.
- Runtime allowlisting still requires the event `userPoolId` and `callerContext.clientId` to match one profile.
- The handler logs a short hash of `userName`, never raw email/user identifiers.
- The first-token guarantee should come from custom signup or a pre-existing correctly configured user. Post-authentication repair is best-effort for the next sign-in.
