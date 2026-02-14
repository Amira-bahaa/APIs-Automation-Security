import pytest

ENDPOINT = "/users/forget-password"


class TestForgetPasswordAuth:

    @pytest.mark.auth
    def test_no_auth_doesnt_crash(self, api, valid_forget_password_payload):
        resp = api.post(ENDPOINT, data=valid_forget_password_payload, headers={"Authorization": ""})
        assert resp.status_code != 500

    @pytest.mark.auth
    def test_invalid_token_doesnt_crash(self, api, valid_forget_password_payload):
        resp = api.post(ENDPOINT, data=valid_forget_password_payload, headers={"Authorization": "garbage_token"})
        assert resp.status_code != 500

    @pytest.mark.auth
    @pytest.mark.injection
    def test_sqli_in_auth_header(self, api, valid_forget_password_payload):
        resp = api.post(
            ENDPOINT, data=valid_forget_password_payload,
            headers={"Authorization": "'; DROP TABLE users; --"}
        )
        assert resp.status_code in [400, 401, 403, 404]
        assert "sql" not in resp.text.lower()
