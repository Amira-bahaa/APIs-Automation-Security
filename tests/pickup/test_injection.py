import pytest
from payloads import SQL_INJECTIONS, XSS_PAYLOADS, NOSQL_INJECTIONS, SSRF_PAYLOADS, SENSITIVE_PATTERNS

ENDPOINT = "/pickups"


class TestPickupInjection:

    @pytest.mark.injection
    @pytest.mark.critical
    @pytest.mark.parametrize("sqli_payload", SQL_INJECTIONS)
    def test_sqli_in_business_location(self, api, auth_token, valid_pickup_payload, sqli_payload):
        payload = valid_pickup_payload.copy()
        payload["businessLocationId"] = sqli_payload
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code != 500, f"Server error with: {sqli_payload}"
        assert "syntax" not in resp.text.lower() and "sql" not in resp.text.lower()

    @pytest.mark.injection
    @pytest.mark.parametrize("sqli_payload", SQL_INJECTIONS)
    def test_sqli_in_contact_name(self, api, auth_token, valid_pickup_payload, sqli_payload):
        payload = valid_pickup_payload.copy()
        payload["contactPerson"] = valid_pickup_payload["contactPerson"].copy()
        payload["contactPerson"]["name"] = sqli_payload
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code != 500

    @pytest.mark.injection
    @pytest.mark.parametrize("xss_payload", XSS_PAYLOADS)
    def test_xss_in_creation_source(self, api, auth_token, valid_pickup_payload, xss_payload):
        payload = valid_pickup_payload.copy()
        payload["creationSrc"] = xss_payload
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert "<script>" not in resp.text

    @pytest.mark.injection
    @pytest.mark.parametrize("xss_payload", XSS_PAYLOADS)
    def test_xss_in_contact_name(self, api, auth_token, valid_pickup_payload, xss_payload):
        payload = valid_pickup_payload.copy()
        payload["contactPerson"] = valid_pickup_payload["contactPerson"].copy()
        payload["contactPerson"]["name"] = xss_payload
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert "<script>" not in resp.text

    @pytest.mark.injection
    @pytest.mark.parametrize("ssrf_url", SSRF_PAYLOADS)
    def test_ssrf_in_email(self, api, auth_token, valid_pickup_payload, ssrf_url):
        payload = valid_pickup_payload.copy()
        payload["contactPerson"] = valid_pickup_payload["contactPerson"].copy()
        payload["contactPerson"]["email"] = ssrf_url
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code != 500

    @pytest.mark.injection
    def test_nosql_in_business_location(self, api, auth_token, valid_pickup_payload):
        for nosql in NOSQL_INJECTIONS:
            payload = valid_pickup_payload.copy()
            payload["businessLocationId"] = nosql
            resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
            assert resp.status_code != 500, f"NoSQL error: {nosql}"

    @pytest.mark.data_exposure
    def test_no_sensitive_data_leaked(self, api, auth_token, valid_pickup_payload):
        resp = api.post(ENDPOINT, data=valid_pickup_payload, headers={"Authorization": auth_token})
        body = resp.text.lower()
        for pattern in SENSITIVE_PATTERNS:
            if pattern.lower() in body and pattern in ["password", "ssn", "credit_card", "Traceback", "at com."]:
                pytest.fail(f"Found '{pattern}' in response")

    @pytest.mark.injection
    def test_malformed_json(self, api, auth_token):
        resp = api.post(
            ENDPOINT, raw_body="{ invalid json !!!",
            headers={"Authorization": auth_token, "content-type": "application/json"}
        )
        assert resp.status_code in [400, 422]

    @pytest.mark.injection
    def test_null_byte_injection(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["contactPerson"] = valid_pickup_payload["contactPerson"].copy()
        payload["contactPerson"]["name"] = "test\x00admin"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code != 500
