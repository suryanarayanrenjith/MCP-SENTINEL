# Risk engine: gated cascade + evidence fusion

Risk is decided in two stages:

1. **Hard gates.** These are binary and run first: identity, agent binding, server/tool trust, integrity, input validation, RBAC × capability, admin rules, lockdown, data-flow exfiltration and critical runtime deviation. If any gate fails, the decision is **BLOCK**, whatever the score. Neither the LLM nor a good score can override a gate.
2. **Evidence fusion.** Every signal that is not a hard failure becomes a piece of *evidence*: an independent likelihood `pᵢ` that this call is unsafe. The engine combines the evidence with the **impact** of the action and returns a 0–100 score, a band and an obligation.

```
L = 1 − Π (1 − pᵢ)                 noisy-OR fusion: diminishing returns, never above 1
I = impact(action)                  capability, data class, destructiveness, external egress
R = 100 · L · (α + (1 − α) · I)     α = SENTINEL_RISK_ALPHA (default 0.5)
```

The earlier model added points together. Five weak signals would add up past the block threshold, so a normal `get_credentials` call during an investigation was hard-blocked instead of stepped up. With noisy-OR, weak signals have diminishing returns, strong evidence still dominates, and *impact* separates "suspicious but harmless" from "suspicious and dangerous".

## Bands and the response ladder

| Score | Band | Response (`sentinel/response.py`) |
|---|---|---|
| any | hard gate failed | **BLOCK** |
| ≥ 80 | CRITICAL | **BLOCK**: MFA never converts a critical score into an allow |
| — | approval obligation (policy rule, lockdown, changed tool) | **HUMAN_APPROVAL**: single-use and bound to the request hash |
| ≥ 60, or ≥ 40 on a state-changing capability, or an MFA policy obligation | HIGH / SUSPICIOUS | **MFA_REQUIRED** until step-up is satisfied |
| 40–79 with assurance satisfied | SUSPICIOUS / HIGH | **RESTRICT**: executes with strict output sanitisation (secrets redacted, injections quarantined) |
| 20–39 | MONITOR | **MONITOR**: executes with heightened monitoring |
| < 20 | NORMAL | **ALLOW** |

All thresholds are configurable: `SENTINEL_RESTRICT_RISK_THRESHOLD`, `SENTINEL_MFA_RISK_THRESHOLD` and `SENTINEL_BLOCK_RISK_THRESHOLD`.

## Impact

| Capability | Impact |
|---|---|
| READ | 0.25 |
| EXTERNAL_LOOKUP | 0.30 |
| WRITE | 0.50 |
| DATA_TRANSFER | 0.80 |
| SECRET_ACCESS | 0.90 |
| INFRASTRUCTURE_CONTROL | 0.95 |
| CODE_EXECUTION | 1.00 |

Adjustments:

* CRITICAL sensitivity raises impact to 0.9.
* A destructive action adds 0.15.
* SECRET or CRITICAL data raises it to at least 0.9; CONFIDENTIAL data raises it to at least 0.6.
* External egress adds 0.1.

## Evidence sources

| Evidence | Typical p | Source |
|---|---|---|
| `trust_prior` | 0.02 (TRUSTED) to 0.25 (RESTRICTED) | server/tool trust status |
| `integrity_drift`, `unreviewed_tool`, `tool_metadata`, `supply_chain` | 0.05–0.6 | discovery / scanner / supply-chain analysis |
| input soft findings, `prompt_injection_args` | 0.2–0.5 | `sentinel/validation.py`, `sentinel/injection.py` |
| `sequence_transition` | 0.15–0.5 | e.g. EXTERNAL_LOOKUP → SECRET_ACCESS 0.35; SECRET_ACCESS → DATA_TRANSFER 0.5; EXTERNAL_LOOKUP → CODE_EXECUTION 0.35 |
| `privilege_escalation`, probing, velocity | 0.15–0.4 | `workflow/analyzer.py` |
| `intent_mismatch` | 0.3 | `workflow/context_engine.py` |
| `lethal_trifecta`, `confidential_transfer`, `secret_then_egress` | 0.2–0.7 | `dataflow/guard.py` |
| `behavior_drift`, `runtime`, `sandbox` | up to 0.6–0.9 | behavioural baseline, process monitor, honeypot |
| `authn_assurance` | 0.25 | the call is sensitive and no MFA context is present |
| `workflow_memory` | ≤ 0.6 | decayed anomalies from earlier calls in the same workflow |

### Workflow risk memory

Zero trust re-evaluates continuously, so suspicion carries over between calls. Anomalies (category `anomaly`, `dataflow` or `runtime`, with p ≥ 0.15) are remembered per workflow and keyed by kind. They decay with a half-life of `SENTINEL_RISK_MEMORY_HALF_LIFE_SECONDS` (600 s by default). Before reuse they are damped (× 0.6) and capped at 0.6. When the current call already carries a kind of evidence, the remembered evidence of that kind is excluded, so an honest retry does not push risk up step by step. Structural signals such as the lethal trifecta are recomputed on every call rather than remembered.

## Explainability: the risk waterfall

Each factor's displayed contribution is its share of `−ln(1 − pᵢ)`. The contributions add up to the final score, so the dashboard can draw an additive waterfall. Every receipt stores the factors, `likelihood`, `impact`, `impact_reasons` and the full gate trace.

### Worked example (from `python -m sentinel.demo`, scenario 2)

`soc__get_credentials` runs right after `soc__lookup_ip` in a workflow whose intent is "Investigate suspicious activity…":

| Factor | p | Contribution |
|---|---|---|
| sequence_transition: EXTERNAL_LOOKUP → SECRET_ACCESS | 0.35 | 23 |
| intent_mismatch: a critical capability does not follow from an investigation-only intent | 0.30 | 19 |
| authn_assurance: no MFA context | 0.25 | 16 |
| privilege_escalation: monotonic escalation | 0.15 | 9 |
| trust_prior: TRUSTED | 0.02 | 1 |

L = 1 − (0.65 · 0.70 · 0.75 · 0.85 · 0.98) = **0.7157**. Impact = **0.9** (SECRET_ACCESS, SECRET data). R = 100 · 0.7157 · (0.5 + 0.5 · 0.9) = **68**, which is HIGH, so the decision is **MFA_REQUIRED**.

After a TOTP step-up, `authn_assurance` disappears and the score drops to **59** (SUSPICIOUS). The call executes as **RESTRICT**, so the returned secret is redacted. The following `send_data` to an external URL is a hard data-flow **BLOCK** (100).

## Swapping the model

The scoring model is isolated in `risk/engine.py` (`RiskEngine.assess` and `RiskEngine.impact`). The pipeline only builds a list of `Evidence(name, likelihood, reason, category)` and an impact value, so a different fusion function (a Bayesian network, a learned model or a weighted sum) can replace `assess` without touching the gates, the obligations or the receipts.
