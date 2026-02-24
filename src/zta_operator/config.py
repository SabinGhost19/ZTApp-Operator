import os

GROUP = "devsecops.licenta.ro"
VERSION = "v1"
PLURAL = "zerotrustapplications"
KIND = "ZeroTrustApplication"

ZTS_PLURAL = "zerotrustsecrets"
ZTS_KIND = "ZeroTrustSecret"

EXTERNAL_SECRETS_GROUP = "external-secrets.io"
EXTERNAL_SECRETS_VERSION = "v1beta1"
EXTERNAL_SECRETS_PLURAL = "externalsecrets"

ZTS_MANAGED_LABEL_KEY = "zta.devsecops/managed-secret"
ZTS_MANAGED_LABEL_VALUE = "true"
ZTS_LABEL_NAME = "zta.devsecops/zts-name"
ZTS_LABEL_NAMESPACE = "zta.devsecops/zts-namespace"

SCA_PLURAL = "supplychainattestations"
SCA_KIND = "SupplyChainAttestation"

DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"

TALON_NAMESPACE = os.getenv("TALON_NAMESPACE", "falco-talon")
TALON_CONFIGMAP_NAME = os.getenv("TALON_CONFIGMAP_NAME", "falco-talon-rules")
TALON_CONFIGMAP_KEY = os.getenv("TALON_CONFIGMAP_KEY", "rules.yaml")

FALCO_RULE_LABEL_KEY = os.getenv("FALCO_RULE_LABEL_KEY", "falco.org/rule")
FALCO_RULE_LABEL_VALUE = os.getenv("FALCO_RULE_LABEL_VALUE", "true")

COSIGN_BIN = os.getenv("COSIGN_BIN", "cosign")
TRIVY_BIN = os.getenv("TRIVY_BIN", "trivy")
VERIFY_TIMEOUT_SECONDS = int(os.getenv("VERIFY_TIMEOUT_SECONDS", "120"))
TRIVY_TIMEOUT_SECONDS = int(os.getenv("TRIVY_TIMEOUT_SECONDS", "180"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

WASM_PLUGIN_API_VERSION = "extensions.istio.io/v1alpha1"
WASM_PLUGIN_KIND = "WasmPlugin"
