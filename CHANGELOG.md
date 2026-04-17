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
