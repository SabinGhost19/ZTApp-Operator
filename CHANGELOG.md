## [1.8.2](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.8.1...v1.8.2) (2026-05-25)


### Bug Fixes

* **sca-crd,ui:** admit new policy fields + handle ZTA deletion live ([1b1f88f](https://github.com/SabinGhost19/ZTApp-Operator/commit/1b1f88f54636616320a21a3032806b815ac64344))

## [1.8.1](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.8.0...v1.8.1) (2026-05-25)


### Bug Fixes

* **ui:** coerce v-for index to number in ReconcileFlow.vue ([9a17620](https://github.com/SabinGhost19/ZTApp-Operator/commit/9a1762091c5a7157eda1deb08ff92e5c4f8ccd85))

# [1.8.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.7.0...v1.8.0) (2026-05-25)


### Features

* structured error taxonomy across operator, backend, SSE and UI ([f93505c](https://github.com/SabinGhost19/ZTApp-Operator/commit/f93505cb96eacabca791e45e9ca7501c719c7b49))

# [1.7.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.6.1...v1.7.0) (2026-05-21)


### Features

* **zta-operator:** ingest SBOM/VEX via guacone to bypass DSSE verification ([532c345](https://github.com/SabinGhost19/ZTApp-Operator/commit/532c34556d0810ae30e4246b48b3bd37dd21b63c))

## [1.6.1](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.6.0...v1.6.1) (2026-05-21)


### Bug Fixes

* **zta-operator:** send DATATYPE_OCI_REGISTRY instead of OCI digest to collectsub ([e25e5cf](https://github.com/SabinGhost19/ZTApp-Operator/commit/e25e5cf84e9814c44b4f5fd6979090b41c8fcc0b))

# [1.6.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.5.3...v1.6.0) (2026-05-21)


### Features

* **guac:** expose visualizer and graphql via nginx ingress ([15088f8](https://github.com/SabinGhost19/ZTApp-Operator/commit/15088f8ca7dadbe999dad5312c7e9a458abcad6a))

## [1.5.3](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.5.2...v1.5.3) (2026-05-20)


### Bug Fixes

* **guac-client:** fix dead enpoint ([b34a318](https://github.com/SabinGhost19/ZTApp-Operator/commit/b34a31874c85cf7a309d07c81ca1657c843c4bc6))

## [1.5.2](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.5.1...v1.5.2) (2026-05-20)


### Bug Fixes

* **guac:** align default service URLs with the official guacsec/guac chart ([deeb3d6](https://github.com/SabinGhost19/ZTApp-Operator/commit/deeb3d6b48a23691301e0a224a7e8cc648eff2e3))
* **operators:** isolate kopf progress/diffbase storage per operator ([e41cca5](https://github.com/SabinGhost19/ZTApp-Operator/commit/e41cca5fa9762150905e56c525cfc23676f28c13))

## [1.5.1](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.5.0...v1.5.1) (2026-05-20)


### Bug Fixes

* **guac:** align default service URLs with the official guacsec/guac chart ([b28b7fd](https://github.com/SabinGhost19/ZTApp-Operator/commit/b28b7fdfee0d7296345a04b782be6bfa8fef4685))

# [1.5.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.4.2...v1.5.0) (2026-05-20)


### Features

* **supply-chain:** RFC 6962 Merkle + Audit-mode + webhook + CEL + VEX + KubeArmor + GUAC ([dfcdd0f](https://github.com/SabinGhost19/ZTApp-Operator/commit/dfcdd0f8ce5858189766e2a38ebe6f28bba2b82e))

## [1.4.2](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.4.1...v1.4.2) (2026-05-12)


### Bug Fixes

* **operator:** persist spec hash via CRD schema + annotation fallback ([2ed7358](https://github.com/SabinGhost19/ZTApp-Operator/commit/2ed735889995beb527b0b57291ee2524052fa5c8))

## [1.4.1](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.4.0...v1.4.1) (2026-05-12)


### Bug Fixes

* **operator:** break reconcile loop with spec-hash idempotency guard ([412459c](https://github.com/SabinGhost19/ZTApp-Operator/commit/412459c08494be14f4645ce0c8c550e857129926))

# [1.4.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.10...v1.4.0) (2026-05-12)


### Features

* **ui:** horizontal CI/CD pipeline + granular sub-task forensics ([c497195](https://github.com/SabinGhost19/ZTApp-Operator/commit/c49719537e6d204c59a3264e6bb84c0049d80f18))

## [1.3.10](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.9...v1.3.10) (2026-05-11)


### Bug Fixes

* RBAC guards, JIT token flow, ZTA polling stability and operator namespace alignment ([de0b111](https://github.com/SabinGhost19/ZTApp-Operator/commit/de0b1112b2d45c1364ab3616cd2fa84d046dfe37))

## [1.3.9](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.8...v1.3.9) (2026-04-18)


### Bug Fixes

* reconcile zta resource ([5285ef8](https://github.com/SabinGhost19/ZTApp-Operator/commit/5285ef8757a3de92655df88b046ee83256a36571))

## [1.3.8](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.7...v1.3.8) (2026-04-18)


### Bug Fixes

* reconcile ui ([65e8429](https://github.com/SabinGhost19/ZTApp-Operator/commit/65e8429761d69743f7aae459be04659dfb68a9d4))

## [1.3.7](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.6...v1.3.7) (2026-04-18)


### Bug Fixes

* reconcile ui ([d32e0eb](https://github.com/SabinGhost19/ZTApp-Operator/commit/d32e0eb131918c7a8fd59924e2dc9e335d2aca83))

## [1.3.6](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.5...v1.3.6) (2026-04-18)


### Bug Fixes

* **zta-runtime:** stop modifiing status trusted ([08a35f4](https://github.com/SabinGhost19/ZTApp-Operator/commit/08a35f404c6197a50a7cbc77f8edbf593b861cd9))

## [1.3.5](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.4...v1.3.5) (2026-04-17)


### Bug Fixes

* **zta-runtime:** stop status reconcile loops and disable readonly rootfs when runtimeSecurity is absent ([cab91aa](https://github.com/SabinGhost19/ZTApp-Operator/commit/cab91aae246ac4a028c6e242ab3e955c846ae7f8))

## [1.3.4](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.3...v1.3.4) (2026-04-17)


### Bug Fixes

* **zta-operator:** skip Istio and Falco resources when ZTA spec omits wafConfig and runtimeSecurity ([2154c29](https://github.com/SabinGhost19/ZTApp-Operator/commit/2154c2926c28be6be69f5148be0da6760d79640b))

## [1.3.3](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.2...v1.3.3) (2026-04-17)


### Bug Fixes

* **zta:** duplicated tracing logs ([2d8ed77](https://github.com/SabinGhost19/ZTApp-Operator/commit/2d8ed77c8a3a96d1449abc0cb1ddb24a3e2f2e25))

## [1.3.2](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.1...v1.3.2) (2026-04-17)


### Bug Fixes

* **zta:** anifest spec hash mismatch ([956be4f](https://github.com/SabinGhost19/ZTApp-Operator/commit/956be4fefbbe35dba6bb93fcd01783dab84438b0))

## [1.3.1](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.3.0...v1.3.1) (2026-04-17)


### Bug Fixes

* **zta:** reconcile on trust level updates and allow event emission ([a630a50](https://github.com/SabinGhost19/ZTApp-Operator/commit/a630a50ff3823dfdacfd56052d030c4a4669ff99))

# [1.3.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.2.0...v1.3.0) (2026-04-16)


### Features

* provenance enforcer added ([613c945](https://github.com/SabinGhost19/ZTApp-Operator/commit/613c94560869f8e09554d76411da238d325b8040))

# [1.2.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.1.4...v1.2.0) (2026-02-25)


### Features

* added logging for sca resource reconcile ([f001d7b](https://github.com/SabinGhost19/ZTApp-Operator/commit/f001d7bd196abb5014224cade04a3370db67ac87))

## [1.1.4](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.1.3...v1.1.4) (2026-02-25)


### Bug Fixes

* recursive reconcile per zta spec ([b2f30a5](https://github.com/SabinGhost19/ZTApp-Operator/commit/b2f30a511ebc17c2ed7dd9cb78d9fd205bab84b1))

## [1.1.3](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.1.2...v1.1.3) (2026-02-25)


### Bug Fixes

* jsonable traversal in operator ([3df7e20](https://github.com/SabinGhost19/ZTApp-Operator/commit/3df7e20058e98f8b96c449895bc6d807555e7876))

## [1.1.2](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.1.1...v1.1.2) (2026-02-24)


### Bug Fixes

* rbac patch and delete for SCA ([63fdd98](https://github.com/SabinGhost19/ZTApp-Operator/commit/63fdd98ff22e302329625f8660f2b9cf4711af0f))

## [1.1.1](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.1.0...v1.1.1) (2026-02-24)


### Bug Fixes

* v1.0.3 added ([a12529e](https://github.com/SabinGhost19/ZTApp-Operator/commit/a12529ea4e60e8f2dfd3aaaf41f81f167ae164e9))

# [1.1.0](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.0.2...v1.1.0) (2026-02-24)


### Features

* SCA crd added with zta selector ([137cd8e](https://github.com/SabinGhost19/ZTApp-Operator/commit/137cd8ecec9ad61c6b86f7e1a1435defc3c959ac))

## [1.0.2](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.0.1...v1.0.2) (2026-02-23)


### Bug Fixes

* realeaserc successComment: false ([951eb15](https://github.com/SabinGhost19/ZTApp-Operator/commit/951eb1517d9b0c3500dbc042bf401d10558fe630))

## [1.0.1](https://github.com/SabinGhost19/ZTApp-Operator/compare/v1.0.0...v1.0.1) (2026-02-23)


### Bug Fixes

* default attestation name ([19fc8d9](https://github.com/SabinGhost19/ZTApp-Operator/commit/19fc8d9fec3d1c66d9f2dd0b9cd74f16b43d7b0f))

# 1.0.0 (2026-02-23)


### Bug Fixes

* **ci:** added new image version tag ([1ecc622](https://github.com/SabinGhost19/ZTApp-Operator/commit/1ecc622a23830dc5b19078bc64d2bd8e2cef7198))
* zta-operator useraip nonnumeric error ([10b8657](https://github.com/SabinGhost19/ZTApp-Operator/commit/10b86572d0e6aa22239c279310868e3599b89f96))
* **zts:** repaird serialization ([d37b0d2](https://github.com/SabinGhost19/ZTApp-Operator/commit/d37b0d29d1e5a83efcdaf036d967d60363dc3128))


### Features

* add SupplyChainAttestation compatibility ([9176ccc](https://github.com/SabinGhost19/ZTApp-Operator/commit/9176ccce02c2bfb0c02bb4a37aae8d6a952a8796))
* zero trust secret crd added ([ec11b3b](https://github.com/SabinGhost19/ZTApp-Operator/commit/ec11b3ba458857bf7dc31a18bd2e4dea37d1b0aa))
* zta operator bootstrap ([5b93fd6](https://github.com/SabinGhost19/ZTApp-Operator/commit/5b93fd64813b838d4e37a9b8b212086d279493d4))
