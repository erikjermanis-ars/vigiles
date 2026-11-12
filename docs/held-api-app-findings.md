# held-api: application-level security issues (outside Vigiles' scope)

2026-11-11 · Found while profiling held-api `origin/main` @ 7cab81c9. Everything here was read from the repository; nothing was tested against production.

Vigiles watches **dependencies** for known vulnerabilities. The issues below are in held-api's **own code and configuration**, so Vigiles will never alert on them. Some are more serious than any dependency finding in this project. They are listed for the team to review, most important first.

| # | Issue | Why it matters | Where |
|---|---|---|---|
| 1 | **Anonymous endpoint makes the server download arbitrary URLs.** `POST /session-blueprints/promote` is marked "Temporarily open (no auth required)". Anyone can create or update session drafts, and media URLs in the payload are fetched server-side with axios. | Server-side request forgery from the internet. On ECS, internal addresses (task metadata, private services) may be reachable, and attacker content ends up in the media S3 bucket. | `backend/src/session-blueprint/*` (`@Public` promote handler), `managed-file/file.service.ts` |
| 2 | **Firebase sign-in maps users by e-mail without checking `email_verified`.** `getUserByFirebaseUidOrEmail` links a token to an existing user by uid *or* e-mail. | If the Firebase project allows sign-up with an unverified e-mail, someone could register with a staff or admin address and act as that account. Whether this works depends on Firebase project settings, which aren't in the repo. **Check this first.** | `backend/src/firebase/firebase.service.ts` |
| 3 | **Long-lived secrets in image layers and in Sentry.** `DATABASE_URL` and `SENTRY_AUTH_TOKEN` are build args persisted as image ENV. Sentry runs with `sendDefaultPii: true` at 100% tracing. A known Sentry SDK bug (Vigiles finding #136–138) also records `Authorization`/`Cookie` headers. LoginSession ids have no expiry. | Anyone who can read the image or the Sentry project can get database credentials and reusable session tokens, including staff and admin ones. | `backend/aws/Dockerfile`, `initialize-sentry.ts`, `prisma/login-session.prisma` |
| 4 | **No rate limiting anywhere, and a 300 MB JSON body limit.** There is no `@nestjs/throttler`, `express-rate-limit`, WAF config or helmet. | Every denial-of-service finding (multer, body-parser, zod) is easier to abuse. Brute-forcing `/auth/login` is unthrottled. | `backend/src/main.ts` |
| 5 | **App Store server notifications are not signature-checked.** The JWS is base64-decoded without verification. | It's mitigated, because subscription state is then re-fetched from Apple by transaction id. Still worth verifying the signature. | `backend/src/app-store/*` |
| 6 | **Other always-public surfaces.** `POST /auth/hash` (returns a bcrypt hash of any input) and Swagger UI with the full API schema at `/` are always on. | They give attackers a free map of the API and a CPU-heavy endpoint. | `backend/src/auth/*`, `main.ts` |

**Suggested next step:** a short application security review of held-api, starting with #2 (check the Firebase project settings) and #1 (put the promote endpoint behind the promote API key or an admin check).
