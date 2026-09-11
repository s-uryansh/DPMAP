# Engineering Quality Baseline v1

**Status:** Product-owner authorized engineering default  
**Production compliance guidance:** No  
**External DPO/legal review:** Pending

## Authorization

On 11 September 2026, the project owner authorized the agent to act as the interim product/DPO decision-maker for build-plan Open Questions 4-6 and adopt conservative defaults. These defaults unblock engineering tests; they do not state the law, determine compliance, or replace qualified DPO/legal review before production use.

## Adopted Defaults

- Optimize detector release gates for precision because false accusations create expensive audit work. Required precision/recall and minimum evaluation-set sizes are stored in the versioned assessment rules.
- Limit person-name detection to English and Indian names written in Latin script. Hindi and other regional scripts remain explicitly unassessed and disabled.
- Use deterministic risk bands.
- Treat missing control evidence as unknown, never absent. Unknown/partial controls produce amber review; access/coverage failure produces grey; red requires a confirmed absent control plus score at least 7.
- Collect only the governance and evidence fields named in the versioned rules. Evidence references must identify a policy/control record and must never contain target credentials or matched source values.

## Heatmap Meanings

| Band | Engineering meaning |
|---|---|
| Red | Confirmed high-impact identifier and confirmed control gap meeting the configured threshold |
| Amber | PII found with incomplete/unknown evidence, a partial control, or a lower-scoring confirmed gap |
| Green | Complete scan with no engine-detected storage gap under the evidence provided; not a compliance certificate |
| Grey | Failed, unassessed, or materially incomplete coverage |

## Review Checklist

- [x] Product owner authorized interim engineering defaults for Open Questions 4-6.
- [x] Heatmap colors have explicit non-legal meanings and do not treat unknown as absent.
- [x] Legal sources and their current effective status are versioned with the rules.
- [x] Synthetic seed cases cover positives and near misses for every built-in detector.
- [x] Corpus contains no production-derived or knowingly real personal data; the Aadhaar positive uses UIDAI's published sandbox value.
- [x] Regional-language name detection is visibly excluded.
- [ ] Qualified DPO/legal review completed before production use.
- [ ] Full domain-representative corpus meets configured minimum size and precision/recall gates.

## Sources

- [DPDP Act, 2023](https://www.indiacode.nic.in/bitstream/123456789/22037/2/a2023-22.pdf)
- [DPDP Rules, 2025](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf)
- [DPDP commencement notification](https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf)
- [UIDAI developer sandbox example](https://uidai.gov.in/en/915-developer-section/tutorial-section.html)
- [spaCy EntityRecognizer limitations](https://spacy.io/api/entityrecognizer)
