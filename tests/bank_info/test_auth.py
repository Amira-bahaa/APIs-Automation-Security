import pytest
from payloads import ESCALATION_ROLES
from framework.token_utils import decode_jwt_unsafe, forge_token_none_alg, forge_token_role_escalation

ENDPOINT = "/businesses/add-bank-info"


class TestBankInfoAuthentication:

    @pytest.mark.auth
    @pytest.mark.critical
    def test_no_auth_rejected(self, api, valid_bank_payload):
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": ""})
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    def test_invalid_jwt_rejected(self, api, valid_bank_payload):
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": "invalid_jwt_string_12345"})
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    def test_truncated_jwt_rejected(self, api, bank_token, valid_bank_payload):
        parts = bank_token.split(".")
        truncated = parts[0] + "." + parts[1][:10] if len(parts) > 1 else bank_token[:30]
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": truncated})
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    @pytest.mark.critical
    def test_jwt_claims_inspection(self, bank_token):
        claims = decode_jwt_unsafe(bank_token)
        if claims is None:
            pytest.skip("Not a JWT")

        assert "exp" in claims, "No expiration in JWT"
        for field in ["password", "secret", "ssn"]:
            assert field not in claims, f"Sensitive field in JWT: {field}"

    @pytest.mark.auth
    @pytest.mark.critical
    def test_alg_none_attack(self, api, bank_token, valid_bank_payload):
        claims = decode_jwt_unsafe(bank_token)
        if not claims:
            pytest.skip("Can't decode token")
        forged = forge_token_none_alg(claims)
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": forged})
        assert resp.status_code in [401, 403], f"alg=none accepted! status={resp.status_code}"

    @pytest.mark.auth
    @pytest.mark.critical
    @pytest.mark.parametrize("role", ESCALATION_ROLES)
    def test_role_escalation(self, api, bank_token, valid_bank_payload, role):
        forged = forge_token_role_escalation(bank_token, target_role=role)
        if not forged:
            pytest.skip("Could not forge token")
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": forged})
        assert resp.status_code in [401, 403], f"Escalated to {role}!"

    @pytest.mark.auth
    def test_bearer_invalid_jwt(self, api, valid_bank_payload):
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": "Bearer invalidjwt.payload.sig"})
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    @pytest.mark.injection
    def test_sqli_in_auth_header(self, api, valid_bank_payload):
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": "'; DROP TABLE users; --"})
        assert resp.status_code in [400, 401, 403]
        assert "sql" not in resp.text.lower()
