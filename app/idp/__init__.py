# app/idp package — Enterprise IdP / JWT integration layer.
#
# Modules:
#   oidc_discovery  — OIDC discovery endpoint fetch + metadata cache
#   jwks_client     — JWKS key fetch + kid-based cache + key-rotation handling
#   jwt_validator   — JWT signature validation + claim extraction
#   group_mapper    — IdP group → internal masking role mapping store
