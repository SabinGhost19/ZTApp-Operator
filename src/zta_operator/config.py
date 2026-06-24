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

# Seconds between periodic ZeroTrustSecret re-evaluations (real ExternalSecret
# sync check + continuous trust re-evaluation / hard revoke). Drives the
# @kopf.timer in zerotrust_secret.py. Default 5 min: the create/update handlers
# react immediately to ZTS changes, so this timer only catches *external* drift
# (Vault/ESO sync loss, trust revocation, rotation) — a few minutes of latency
# there is an acceptable trade-off for far less reconcile churn and log noise.
# Tunable via the ZTS_HEALTH_INTERVAL env var if faster drift detection is wanted.
ZTS_HEALTH_INTERVAL = int(os.getenv("ZTS_HEALTH_INTERVAL", "300"))

SCA_PLURAL = "supplychainattestations"
SCA_KIND = "SupplyChainAttestation"

DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"

# Talon lives in the `falco` namespace on the authoritative Helm/GitOps path
# (infra-tools .../falco/helm-release-talon.yaml: metadata.namespace=falco; the
# operator Helm chart sets TALON_NAMESPACE=falco via falcoTalonRbac.namespace).
# The default below must match that reality; the env override lets Helm/dev set it.
TALON_NAMESPACE = os.getenv("TALON_NAMESPACE", "falco")
TALON_CONFIGMAP_NAME = os.getenv("TALON_CONFIGMAP_NAME", "falco-talon-rules")
TALON_CONFIGMAP_KEY = os.getenv("TALON_CONFIGMAP_KEY", "rules.yaml")

FALCO_RULE_LABEL_KEY = os.getenv("FALCO_RULE_LABEL_KEY", "falco.org/rule")
FALCO_RULE_LABEL_VALUE = os.getenv("FALCO_RULE_LABEL_VALUE", "true")

COSIGN_BIN = os.getenv("COSIGN_BIN", "cosign")
TRIVY_BIN = os.getenv("TRIVY_BIN", "trivy")
VERIFY_TIMEOUT_SECONDS = int(os.getenv("VERIFY_TIMEOUT_SECONDS", "120"))
TRIVY_TIMEOUT_SECONDS = int(os.getenv("TRIVY_TIMEOUT_SECONDS", "180"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

INGRESS_CLASS_NAME = os.getenv("INGRESS_CLASS_NAME", "nginx")
INGRESS_PATH = os.getenv("INGRESS_PATH", "/")
INGRESS_PATH_TYPE = os.getenv("INGRESS_PATH_TYPE", "Prefix")

OAUTH2_AUTH_URL = os.getenv(
    "OAUTH2_AUTH_URL",
    "http://oauth2-proxy.oauth2-proxy.svc.cluster.local/oauth2/auth",
)
OAUTH2_AUTH_SIGNIN = os.getenv(
    "OAUTH2_AUTH_SIGNIN",
    "https://{host}/oauth2/start?rd=$escaped_request_uri",
)
OAUTH2_AUTH_RESPONSE_HEADERS = os.getenv(
    "OAUTH2_AUTH_RESPONSE_HEADERS",
    "X-Auth-Request-User, X-Auth-Request-Email, X-Auth-Request-Groups",
)
OAUTH2_GROUPS_HEADER = os.getenv("OAUTH2_GROUPS_HEADER", "X-Forwarded-Groups")
OAUTH2_GROUPS_HEADER_FALLBACK = os.getenv("OAUTH2_GROUPS_HEADER_FALLBACK", "X-Auth-Request-Groups")
OAUTH2_PROXY_SERVICE_NAME = os.getenv("OAUTH2_PROXY_SERVICE_NAME", "oauth2-proxy")
OAUTH2_PROXY_NAMESPACE = os.getenv("OAUTH2_PROXY_NAMESPACE", "oauth2-proxy")
OAUTH2_PROXY_PORT = int(os.getenv("OAUTH2_PROXY_PORT", "80"))
OAUTH2_INGRESS_PATH = os.getenv("OAUTH2_INGRESS_PATH", "/oauth2")

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

WASM_PLUGIN_API_VERSION = "extensions.istio.io/v1alpha1"
WASM_PLUGIN_KIND = "WasmPlugin"
