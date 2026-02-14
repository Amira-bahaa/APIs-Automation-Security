import pytest
from payloads import SQL_INJECTIONS
from framework.token_utils import decode_jwt_unsafe, forge_token_none_alg, forge_token_role_escalation

ENDPOINT = "/pickups"


class TestPickupAuthentication:

    @pytest.mark.auth
    @pytest.mark.critical
    def test_no_auth_header_rejected(self, api, valid_pickup_payload):
        resp = api.post(ENDPOINT, data=valid_pickup_payload, headers={"Authorization": ""})
        assert resp.status_code in [401, 403], f"Got {resp.status_code} without auth"

    @pytest.mark.auth
    def test_empty_token_rejected(self, api, valid_pickup_payload):
        resp = api.post(ENDPOINT, data=valid_pickup_payload, headers={"Authorization": ""})
        assert resp.status_code in [400, 401, 403]

    @pytest.mark.auth
    def test_garbage_token_rejected(self, api, valid_pickup_payload):
        resp = api.post(
            ENDPOINT, data=valid_pickup_payload,
            headers={"Authorization": "completely_invalid_random_token_xyz"}
        )
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    def test_truncated_token_rejected(self, api, auth_token, valid_pickup_payload):
        partial = auth_token[:20]
        resp = api.post(ENDPOINT, data=valid_pickup_payload, headers={"Authorization": partial})
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    def test_modified_token_rejected(self, api, auth_token, valid_pickup_payload):
        tampered = auth_token[:-1] + ("X" if auth_token[-1] != "X" else "Y")
        resp = api.post(ENDPOINT, data=valid_pickup_payload, headers={"Authorization": tampered})
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    def test_bearer_prefix_invalid_token(self, api, valid_pickup_payload):
        resp = api.post(
            ENDPOINT, data=valid_pickup_payload,
            headers={"Authorization": "Bearer fake_token_value"}
        )
        assert resp.status_code in [401, 403]

    @pytest.mark.auth
    @pytest.mark.injection
    def test_sqli_in_auth_header(self, api, valid_pickup_payload):
        resp = api.post(
            ENDPOINT, data=valid_pickup_payload,
            headers={"Authorization": "'; DROP TABLE users; --"}
        )
        assert resp.status_code in [400, 401, 403]
        assert "sql" not in resp.text.lower()

    @pytest.mark.auth
    @pytest.mark.critical
    def test_admin_endpoints_blocked(self, api, auth_token):
        admin_paths = ["/admin/pickups", "/pickups/admin", "/internal/pickups"]
        for path in admin_paths:
            resp = api.get(path, headers={"Authorization": auth_token})
            assert resp.status_code in [401, 403, 404], f"{path} returned {resp.status_code}"
