# Coverage annex — Compat policy gates + IoT Security guidance (23-80986-022)

Document `23-80986-022`, v1.1 (June 2026). Prior state: 1061 anchors, 0 covered (0.00%).

Owned crates: `rounddance-compat` (admission/negotiation policy). New tests: `crates/rounddance-compat/tests/coverage_policy_compat_iotsec.rs`. Expectation set honestly: the IoT-Security document is certification guidance (supplier-system requirements), not wire behavior, so most anchors are N-A-with-cause (guidance / platform-owned); the annex pins only the wire-enforceable projections the stack owns: security-level floor, no silent downgrade, key hygiene (install-code preferred; strict posture refuses weak peers), leave/factory-reset erasure.

Gap anchors listed: 60. Disposition counts this wave: covered-by-test 4, N-A-with-cause 56.

Closed-or-dispositioned: 60/60 (100.0% of prior gaps). All wording below is paraphrase (D1); anchors name pages and corpus line ranges only.

| page | gap anchors | disposition | pin / cause | paraphrase topic |
|---|---|---|---|---|
| p0001 | L1-L15 | N-A (guidance, no wire behavior) | — (certification guidance; see annex prose) | Revision Date June 16, 2026 |
| p0002 | L16, L18-L53 | N-A (guidance, no wire behavior) | — (certification guidance; see annex prose) | Elements of this Specification may be subject to third-party intellectual property rights, 20 |
| p0003 | L54-L55 | N-A (boilerplate) | — | Revision History 57 [page intentionally blank] |
| p0004 | L57 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | Revision History 57 |
| p0006 | L58-L59 | N-A (guidance, no wire behavior) | — (certification guidance; see annex prose) | The following people contributed to this Specification. 59 |
| p0007 | L60-L97 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | Table of Contents 60 |
| p0008 | L98-L138 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 3.30 Security Best Practices 22 98 |
| p0009 | L139-L177 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.4.3.1 Input Data Validation 29 139 |
| p0010 | L178-L218 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 6.2.5 Hardening 37 178 |
| p0011 | L219-L228 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 7.9.1.3 Parental/Guardian Control for Child Access [Provisional] 44 219 |
| p0012 | L229-L230, L232-L267 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 1.1 Purpose 230 |
| p0013 | L268-L305 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | After this initial effort, the PSWG may expand the scope of its work to other sectors (e.g., 268 |
| p0014 | L306-L311, L313, L316-L344 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | the precise requirements and scope of particular government certification programs. 311 |
| p0015 | L345-L355 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | Figure 1-1 provides an example of how an IoT Device, IoT Gateway, IoT App, and IoT 345 |
| p0016 | L356-L369 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | Figure 1-2. Manufacturer (IoT Supplier) sells a Matter-enabled light bulb that works 357 |
| p0017 | L370-L387 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 1.4 Conformance Levels 370 |
| p0018 | L388-L391, L393-L394, L396-L422, L425 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 2 References 388 |
| p0019 | L426-L458 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 3.1 App Platform 427 |
| p0020 | L459-L494 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 3.7 Erasure 459 |
| p0021 | L495-L524 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 3.13 IoT Remote Process 495 |
| p0022 | L525-L559 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 3.23 Product Security Certification 525 |
| p0023 | L560-L581 | covered-by-test | coverage_policy_compat_iotsec.rs (level-0 refusal, floor enforcement, no-silent-downgrade, key hygiene, leave-erasure re-admission) | 3.31 Sensitive Data 564 |
| p0024 | L582 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | CLS Cybersecurity Labeling Scheme |
| p0025 | L583-L608 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.1 Identity and Inventory 595 |
| p0026 | L609-L612, L614-L636 | covered-by-test | coverage_policy_compat_iotsec.rs (level-0 refusal, floor enforcement, no-silent-downgrade, key hygiene, leave-erasure re-admission) | 5.2 IoT System Configuration 609 |
| p0027 | L637-L656 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.2.3.3 Preventing Brute Force Attacks 639 |
| p0028 | L657-L677 | covered-by-test | coverage_policy_compat_iotsec.rs (level-0 refusal, floor enforcement, no-silent-downgrade, key hygiene, leave-erasure re-admission) | 5.2.3.8 Machine-to-Machine Authentication 657 |
| p0029 | L678-L700 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.4 Interfaces 678 |
| p0030 | L701-L722 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.5 Compute 701 |
| p0031 | L723-L742 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.5.5 Software Updates 723 |
| p0032 | L743-L766 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.5.6 State 743 |
| p0033 | L767-L771 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 5.5.8 Isolation 767 |
| p0034 | L772-L805 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 6.1 Documentation 785 |
| p0035 | L806-L832 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 6.1.3 IoT Supplier System Capabilities 809 |
| p0036 | L833-L858 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 6.1.6 Notification of Cybersecurity-Relevant Information 842 |
| p0037 | L859-L863, L865-L882 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 6.2.3 IoT Sub-Components 859 |
| p0038 | L883-L906 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 6.3.2 Vulnerability Response 883 |
| p0039 | L907-L926 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 6.4.3 When Updates Cannot Be Provided 907 |
| p0040 | L927-L944, L946 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 6.5.4 Data Aggregation [Provisional]  927 |
| p0041 | L947-L976 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 7.1 Definitions 956 |
| p0042 | L977-L1002 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 7.2.2 Non-Default Security Parameters [Provisional] 977 |
| p0043 | L1003-L1022 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 7.4.2 Time Stamping 1003 |
| p0044 | L1023-L1047 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 7.8 Secure Boot for Devices Processing Financial Data 1023 |
| p0045 | L1048-L1055 | N-A (guidance, platform-owned) | — (device/platform process requirement; FW/HAL scope, not host-testable here) | 7.9.2 Network Equipment 1048 |
| p0046 | L1056-L1060 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 8.1 Annex I: Coverage of NIST IR 8425 [4] 1058 |
| p0049 | L1061-L1063 | N-A (guidance, no wire behavior) | — (certification guidance; projection pinned only where wire-enforceable) | 8.2 Annex II: Coverage of ETSI EN 303 645 [3] 1061 |
| p0050 | L3 | N-A (guidance, no wire behavior) | — (certification guidance; see annex prose) | 5.3-13 6.1.5 |
| p0052 | L1064-L1069 | N-A (guidance, no wire behavior) | — (certification guidance; see annex prose) | 8.3 Annex III: Coverage of Singapore CSA CLS [5] 1064 |
| p0053 | L1070-L1072 | N-A (guidance, no wire behavior) | — (certification guidance; see annex prose) | 8.4 Annex IV: Coverage of EN 18031-1/2/3 1070 |
| p0055 | L1073 | N-A (guidance, no wire behavior) | — (certification guidance; see annex prose) | EN 18031-1/2/3 Provision Covered by PSWG Provision(s) |
