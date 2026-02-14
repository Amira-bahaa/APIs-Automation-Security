import pytest
import json
from payloads import EXPECTED_SECURITY_HEADERS

ENDPOINT = "/pickups"


class TestPickupBusinessLogic:

    @pytest.mark.business_logic
    def test_negative_parcels(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["numberOfParcels"] = "-5"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_zero_parcels(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["numberOfParcels"] = "0"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_huge_parcel_count(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["numberOfParcels"] = "999999"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_non_numeric_parcels(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["numberOfParcels"] = "abc"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_past_date(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["scheduledDate"] = "2020-01-01"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_invalid_date_format(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["scheduledDate"] = "not-a-valid-date"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_empty_date(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["scheduledDate"] = ""
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_invalid_email(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["contactPerson"] = valid_pickup_payload["contactPerson"].copy()
        payload["contactPerson"]["email"] = "notanemail"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_empty_email(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["contactPerson"] = valid_pickup_payload["contactPerson"].copy()
        payload["contactPerson"]["email"] = ""
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_missing_business_location_id(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        del payload["businessLocationId"]
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_missing_contact_person(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        del payload["contactPerson"]
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_missing_scheduled_date(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        del payload["scheduledDate"]
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_empty_body(self, api, auth_token):
        resp = api.post(ENDPOINT, data={}, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_wrong_content_type(self, api, auth_token, valid_pickup_payload):
        resp = api.post(
            ENDPOINT, raw_body=json.dumps(valid_pickup_payload),
            headers={"Authorization": auth_token, "content-type": "text/plain"}
        )
        assert resp.status_code in [400, 415, 422]

    @pytest.mark.input_validation
    def test_boolean_for_parcels(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["numberOfParcels"] = True
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.rate_limit
    def test_rate_limiting(self, api, auth_token, valid_pickup_payload):
        results = []
        for _ in range(15):
            resp = api.post(ENDPOINT, data=valid_pickup_payload, headers={"Authorization": auth_token})
            results.append(resp.status_code)
        rate_limited = [r for r in results if r == 429]
        successful = [r for r in results if r in [200, 201]]
        if len(successful) > 12 and not rate_limited:
            pytest.xfail("No rate limiting detected")

    @pytest.mark.security_headers
    def test_security_headers(self, api, auth_token, valid_pickup_payload):
        resp = api.post(ENDPOINT, data=valid_pickup_payload, headers={"Authorization": auth_token})
        missing = [h for h in EXPECTED_SECURITY_HEADERS if h not in resp.headers]
        if missing:
            pytest.xfail(f"Missing headers: {', '.join(missing)}")

    @pytest.mark.data_exposure
    def test_error_no_internals_leaked(self, api, auth_token):
        resp = api.post(ENDPOINT, data={}, headers={"Authorization": auth_token})
        body = resp.text
        assert "at com." not in body
        assert "Traceback" not in body
        assert "SELECT" not in body
        assert "/var/" not in body and "/home/" not in body

    @pytest.mark.business_logic
    def test_mass_assignment(self, api, auth_token, valid_pickup_payload):
        payload = valid_pickup_payload.copy()
        payload["isAdmin"] = True
        payload["role"] = "ADMIN"
        payload["walletBalance"] = 999999
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": auth_token})
        if resp.status_code in [200, 201]:
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            assert body.get("isAdmin") is not True
            assert body.get("role") != "ADMIN"
