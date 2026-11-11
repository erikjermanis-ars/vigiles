# POC results

## Round 2 (2026-11-11): labeled, tuned, re-tested

Labels: 54 P0–P2 findings labeled blind by Claude agents applying the owner's rubric (labeler `agent-rubric`). The rubric:
- **ping** means real harm, quickly.
- **digest** means real but not serious; fix within 1–2 weeks.
- **log** means not a real threat.

Three edge-case rulings were added: developer-machine risk → digest; a latent severe flaw in shipped code → digest; severe reachability that can't be ruled out → ping.

| Decider | Matches labels |
|---|---|
| Base priority only (CVSS/EPSS/KEV) | 7 / 54 (13%) |
| Policy v1 × prompt v1 (round 1) | 45 / 54 (83%) |
| Policy v2 × prompt v1 (policy fix only, no LLM calls) | 50 / 54 (93%) |
| **Policy v2 × prompt v2 (rubric in the prompt)** | **54 / 54 (100%)** |

**Consistency** (20 findings triaged twice): the policy action was identical in 20 of 20 (target ≥ 90%). The verdict was identical in 18 of 20; the two differences were a one-step shift (likely vs. definite), with the same action.

**Cost**: 54 + 20 runs on Opus, $7.30 in total. That's $0.10 and 22 s per finding on average.

**Changes**:
- `config/policy.yaml` v2 (`4bea76511f6c`):
  - New `llm-ping` rule.
  - New `p1-clearly-not-affected` → log.
  - `p1-floor` → digest.
  - New `llm-digest`, placed before `tooling-only`.
  - Removed `p1-affected` and `p2-raise`.
- `prompts/triage/v2.system.md`: §7 now contains the owner's rubric and rulings.
- The active config is `v2-opus-high-code`.

**Caveat**: the labels come from the same model family, given the same rubric text that is now in the prompt. 100% shows that Vigiles applies the rubric the way Claude reads it. It does not yet show that it matches the owner's own judgement; validate that with human labels on a sample.

---

## Round 1: first run (before labeling)

2026-11-11 · how-clutch-web `origin/main` @ 9bff790 · active config `v1-opus-high-code` · policy `dca8713daaea`

This is the system's output **before any human labels**. The exit criteria in [poc-spec.md](poc-spec.md) §1 (ping recall and precision, consistency) can only be measured once you have labeled findings on the Review page.

## Funnel

| Stage | Ping | Digest | Log |
|---|---|---|---|
| Severity alone (`npm audit` high + critical, packages) | ~22 packages | — | — |
| Base priority only (P0/P1 → ping, P2 → digest), 118 findings | 9 | 45 | 64 |
| **Policy v1 + Opus triage** | **0** | **10** (6 messages) | **108** |

### The 10 digests

| Finding | Why it is not a ping |
|---|---|
| 5 × `next` P1 RCEs | Verdict *not affected*, high confidence, for the Windows-only RCE. *Likely not affected*, medium confidence, for the image-optimizer SVG/AVIF, `use cache` and `next/og` RCEs: no `images` config, no SVG, no `next/image`, no cache components. The fix is a cheap upgrade to 16.4.1. |
| `storybook`, `@storybook/addon-vitest` P1 | Dev-server only. Production serves a static build. The developer-machine risk is real. |
| `dompurify` P1 | Runs only in the browser through posthog-js, and the vulnerable `SAFE_FOR_TEMPLATES` option is not used. |
| `proxy-addr` P1 | Comes in only through the `shadcn` CLI. |
| `zod` P2 | *Likely affected*: unbounded `z.array(z.uuid())` in `/api/users/update` and `/api/users/invite`, reachable only with a user-management session. That makes it a DoS, so digest. |

Seven of these are P1s that the policy deliberately never silences (`p1-not-affected` → digest). For four of them (the Next.js Windows RCE, dompurify, proxy-addr, Storybook), the LLM's own suggestion was **log**. That is the first tuning question: should a P1 with a high-confidence *not affected* verdict go to log?

## Triage cost and speed (54 runs, Opus, effort high, code access)

| Metric | Value |
|---|---|
| Success rate | 54 / 54 ok (0 invalid, 0 timeouts) |
| Cost, list-price equivalent | **$5.34 total**, $0.10 average per finding |
| Duration | 20.6 s average, 55 s maximum |
| Turns | 5.0 average |
| Production estimate | 118 findings → about 54 P0–P2 triaged at onboarding for about $5. After that, cost scales with *new* findings: at a few per week, under $5 per project per month. |

## Things to look at while labeling

- **Undici** (direct `devDependency`, 2 installed versions): triaged as tooling-only. Check that nothing in `scripts/` runs in production.
- **Storybook dev-server issues** (P2 `GHSA-px85-…`): the LLM suggests *digest* (developer machines at risk), but the `tooling-only` rule logs them. Decide whether developer-machine risk should be digested.
- **sharp/libvips** (3 × P2): *likely not affected*, because there is no images config or `next/image`. Adding `images.remotePatterns` for Supabase storage would change this, and the verdict says so in `exploit_conditions`.

## Next steps

1. Label all 54 P0–P2 findings on **Review**. The labels are blind: you won't see the verdict or decision until you save.
2. Use the disagreements on **Eval** to decide between a policy edit and a prompt change.
3. Run the §11.3 experiments. Start with `v1-sonnet-high-code` and `v1-opus-high-nocode` on the labeled set:

   ```bash
   npm run job -- triage --config v1-sonnet-high-code --limit 60
   npm run job -- triage --config v1-opus-high-nocode --limit 60
   ```

4. Enable held-api (about 170 vulnerable packages across two lockfiles) for volume and variety once its ⚠ profile values are confirmed.
