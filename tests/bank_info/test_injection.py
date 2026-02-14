import pytest
import threading
from payloads import (
    SQL_INJECTIONS, XSS_PAYLOADS, NOSQL_INJECTIONS,
    SSRF_PAYLOADS, OTP_BYPASS_VALUES, EXPECTED_SECURITY_HEADERS,
)

ENDPOINT = "/businesses/add-bank-info"


class TestBankInfoInjection:

    @pytest.mark.injection
    @pytest.mark.parametrize("sqli", SQL_INJECTIONS)
    def test_sqli_in_beneficiary(self, api, bank_token, valid_bank_payload, sqli):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["beneficiaryName"] = sqli
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code != 500
        assert "syntax" not in resp.text.lower()

    @pytest.mark.injection
    @pytest.mark.parametrize("sqli", SQL_INJECTIONS)
    def test_sqli_in_iban(self, api, bank_token, valid_bank_payload, sqli):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["ibanNumber"] = sqli
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code != 500

    @pytest.mark.injection
    @pytest.mark.parametrize("xss", XSS_PAYLOADS)
    def test_xss_in_beneficiary(self, api, bank_token, valid_bank_payload, xss):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["beneficiaryName"] = xss
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert "<script>" not in resp.text

    @pytest.mark.injection
    def test_nosql_in_iban(self, api, bank_token, valid_bank_payload):
        for nosql in NOSQL_INJECTIONS:
            payload = valid_bank_payload.copy()
            payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
            payload["bankInfo"]["ibanNumber"] = nosql
            resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
            assert resp.status_code != 500

    @pytest.mark.injection
    @pytest.mark.parametrize("ssrf_url", SSRF_PAYLOADS)
    def test_ssrf_in_bank_name(self, api, bank_token, valid_bank_payload, ssrf_url):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["bankName"] = ssrf_url
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code != 500


class TestBankInfoOTPBypass:

    @pytest.mark.critical
    @pytest.mark.parametrize("otp_value", OTP_BYPASS_VALUES)
    def test_otp_bypass(self, api, bank_token, valid_bank_payload, otp_value):
        payload = valid_bank_payload.copy()
        payload["paymentInfoOtp"] = otp_value
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        if otp_value in ["", "000000", "' OR '1'='1", "null", "-1"]:
            assert resp.status_code != 200, f"OTP bypass with '{otp_value}'"

    @pytest.mark.critical
    def test_missing_otp(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        del payload["paymentInfoOtp"]
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.injection
    def test_sqli_in_otp(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        payload["paymentInfoOtp"] = "' OR '1'='1"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code != 200


class TestBankInfoValidation:

    @pytest.mark.input_validation
    def test_empty_beneficiary(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["beneficiaryName"] = ""
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_invalid_iban(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["ibanNumber"] = "invalid"
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_empty_iban(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["ibanNumber"] = ""
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_empty_account_number(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["accountNumber"] = ""
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_empty_body(self, api, bank_token):
        resp = api.post(ENDPOINT, data={}, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_missing_bank_info(self, api, bank_token):
        resp = api.post(ENDPOINT, data={"paymentInfoOtp": "123"}, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_malformed_json(self, api, bank_token):
        resp = api.post(
            ENDPOINT, raw_body="{ broken json !!",
            headers={"Authorization": bank_token, "content-type": "application/json"}
        )
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_wrong_type_account_number(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        payload["bankInfo"] = valid_bank_payload["bankInfo"].copy()
        payload["bankInfo"]["accountNumber"] = True
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.business_logic
    def test_mass_assignment(self, api, bank_token, valid_bank_payload):
        payload = valid_bank_payload.copy()
        payload["isAdmin"] = True
        payload["role"] = "SUPER_ADMIN"
        payload["balance"] = 9999999
        resp = api.post(ENDPOINT, data=payload, headers={"Authorization": bank_token})
        if resp.status_code in [200, 201]:
            body = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
            assert body.get("isAdmin") is not True

    @pytest.mark.critical
    def test_race_condition(self, api, bank_token, valid_bank_payload):
        results = []

        def send():
            resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": bank_token})
            results.append(resp.status_code)

        threads = [threading.Thread(target=send) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        successful = [r for r in results if r in [200, 201]]
        if len(successful) > 1:
            pytest.xfail(f"Race condition: {len(successful)}/5 succeeded")

    @pytest.mark.rate_limit
    def test_rate_limiting(self, api, bank_token, valid_bank_payload):
        results = []
        for _ in range(10):
            resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": bank_token})
            results.append(resp.status_code)
        if not any(r == 429 for r in results):
            pytest.xfail("No rate limiting detected")

    @pytest.mark.security_headers
    def test_security_headers(self, api, bank_token, valid_bank_payload):
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": bank_token})
        missing = [h for h in EXPECTED_SECURITY_HEADERS if h not in resp.headers]
        if missing:
            pytest.xfail(f"Missing: {', '.join(missing)}")

    @pytest.mark.data_exposure
    def test_no_info_leaked_in_errors(self, api, bank_token):
        resp = api.post(ENDPOINT, data={}, headers={"Authorization": bank_token})
        body = resp.text
        assert "at com." not in body
        assert "Traceback" not in body
        assert "SELECT" not in body

    @pytest.mark.data_exposure
    def test_no_banking_data_echoed(self, api, bank_token, valid_bank_payload):
        resp = api.post(ENDPOINT, data=valid_bank_payload, headers={"Authorization": bank_token})
        if resp.status_code in [200, 201] and "1234567890123456789012" in resp.text.lower():
            pytest.xfail("Full IBAN echoed back")
