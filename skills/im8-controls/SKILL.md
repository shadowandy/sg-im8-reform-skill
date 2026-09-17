---
name: im8-controls
description: Look up Singapore Government IM8 control catalogs (Cybersecurity and Digital Service Standards/DSS) and System Security Plan (SSP) templates from info.standards.tech.gov.sg. Use when asked about IM8 or GovTech controls, control IDs like as-5, ac-2, lm-8 or wo-2, which controls or level apply to a system (low/medium/high-risk cloud, on-premises, CII, GenAI, sandbox, digital service), control levels 0/1/2, parameters, WCAG/accessibility or usability requirements for government digital services, or drafting, reviewing or gap-checking an SSP. Control text and levels are exact lookups; which controls apply to a scenario is judgement that can be wrong, so present it as a draft for human confirmation.
---

# IM8 Control Catalogs and System Security Plans

This skill bundles the official OSCAL JSON for 26 control catalogs and 8 SSP templates (about 1.7 MB) in `data/`. **Don't read the JSON files directly.** Use `scripts/im8.py`, which needs only Python 3 and returns compact Markdown. Paths are relative to this skill's directory.

```sh
python3 scripts/im8.py list                          # SSP templates (with level counts) and catalog families
python3 scripts/im8.py index [cybersecurity|dss] [FAMILY]   # control IDs and titles, e.g. `index dss wo`
python3 scripts/im8.py control as-5 ac-2             # full text, parameters, and level in every SSP
python3 scripts/im8.py search log retention          # controls matching ALL terms (title, statement, guidance, risk)
python3 scripts/im8.py ssp high-risk-cloud --level 0 # controls in an SSP; filter by --level and/or --family
python3 scripts/im8.py compare dss-others dss-high   # controls whose level or presence differs
```

To go from a topic to a control ID, run `search` first. If it misses (for example because of synonyms), run `index` and read the titles. Cite control IDs and quote statements exactly. Don't paraphrase requirements from memory.

When judging which templates or controls apply to the user's scenario, keep your reasoning separate from the data: state any assumptions (such as data classification or hosting), and say the result is a draft for the security team or system owner to confirm.

## Concepts

- **Catalogs** hold the full definition of each control: its statement, recommendations (guidance), risk statement (Cybersecurity) or rationale (DSS), and parameters. The prefix of a control ID is its family, e.g. `as-5` is in Application Security and `wo-2` is in WCAG: Operable.
- An **SSP template** lists which controls apply to a type of system and the **level** of each one. Agencies customise a template into a system-specific SSP or use it as the default. Statements in an SSP match the catalog word for word.
- **Parameters** appear as `[ac-3_prm_1: time period (days)]` in the script output. The catalog defines each parameter, but neither the catalogs nor the SSP templates set values. The agency chooses the values when it writes its SSP.

| Level | Meaning |
|---|---|
| 0 | Cardinal, mandatory requirements. |
| 1 | Basic process and technical hygiene, including tools that have alternatives. Assess and apply them according to the risk impact. |
| 2 | Best practices to consider and adopt where required. |

A control's level depends on the SSP. For example, `ac-3` is Level 0 in high-risk-cloud but Level 1 in low-risk-cloud.

## Choosing SSP templates

| SSP | Use for |
|---|---|
| `low-risk-cloud` | Low-risk systems hosted on the cloud by a third-party CSP. Sensitivity: up to Restricted / Sensitive Normal. |
| `low-risk-on-premises` | Low-risk on-premises systems. Adds Datacentre (`dc`) and drops Container Security (`cs`). Sensitivity: up to Restricted / Sensitive Normal. |
| `medium-risk-cloud` | Medium-risk cloud systems. Sensitivity: Confidential / Sensitive High. |
| `high-risk-cloud` | High-risk cloud Critical Information Infrastructure (CII). Adds Human Resource (`hr`) and Resiliency (`rs`). CII owners must inform CSA (Cyber Security Agency of Singapore) before migrating to the cloud. Sensitivity: Confidential / Sensitive High. |
| `gen-ai` | Systems that use generative AI models. Always use it **together with** the hosting SSP. Sensitivity: up to Confidential / Sensitive High. |
| `sandbox` | Pilot sandbox systems. Almost every control is Level 2. |
| `dss-others` | Government digital services with **fewer than 1 million visits a year** (WOGAA statistics). |
| `dss-high` | Government digital services with **at least 1 million visits a year**. It has the same controls as dss-others, with more of them at Level 1. |

A public-facing government digital service usually needs **two** SSPs: a security SSP chosen by hosting and risk, and a DSS SSP chosen by traffic. It needs a third, `gen-ai`, if it uses generative AI. The data has no rule for how to combine SSPs. If a control appears in more than one of the chosen SSPs at different levels, point out the difference instead of choosing a level yourself.

## Catalog families

**Cybersecurity** (security): ac Access Control · as Application Security · br Backup and Recovery · ck Cryptography, Encryption and Key Management · cs Container Security · dc Datacentre · dp Data Protection · ga Generative AI · hr Human Resource · is Infrastructure Security · lm Logging and Monitoring · ns Network Security · pm Security Programme Management · rs Resiliency · sc Software Supply Chain · sd Secure Development · st Security Testing

**DSS** (usability, accessibility including WCAG Levels A and AA, transactions, trust): bd Baseline Design Practices · pr Performance and Reliability · tl Trust and Legitimacy · tx Transactions and Payments · uu Understand Users · wo WCAG: Operable · wp WCAG: Perceivable · wr WCAG: Robust · wu WCAG: Understandable

## Raw data (only if the script can't answer)

- Catalog: `data/control-catalog/{cybersecurity,dss}/<family>.json` contains `catalog.groups[0].controls[]`. Each control has `id`, `title`, `parts[]` (`statement` and `guidance` prose), `props[]` (`risk-statement` or `rationale`, and `last-modified`) and an optional `params[]` (`id`, `class`, `label`, `guidelines`).
- SSP: `data/ssp/<name>.json` contains `system-security-plan.control-implementation.implemented-requirements[]`. Each requirement has `control-id`, `props[]` (`control-title` and `profile-level`), the statement in `by-components[0].description`, and `remarks` (recommendations, risk statement, and "Parameters to set").
- Source: https://info.standards.tech.gov.sg. The version date is in each file's `metadata.version`, so mention it if the user needs current guidance.
