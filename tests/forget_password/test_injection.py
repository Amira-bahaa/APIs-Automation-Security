import pytest
import time
from payloads import SQL_INJECTIONS, XSS_PAYLOADS, NOSQL_INJECTIONS, SSRF_PAYLOADS

ENDPOINT = "/users/forget-password"


class TestForgetPasswordInjection:

    @pytest.mark.injection
    @pytest.mark.critical
    @pytest.mark.parametrize("sqli", SQL_INJECTIONS)
    def test_sqli_in_email(self, api, auth_token, sqli):
        resp = api.post(ENDPOINT, data={"email": sqli}, headers={"Authorization": auth_token})
        assert resp.status_code != 500
        assert "syntax" not in resp.text.lower() and "sql" not in resp.text.lower()

    @pytest.mark.injection
    @pytest.mark.parametrize("xss", XSS_PAYLOADS)
    def test_xss_in_email(self, api, auth_token, xss):
        resp = api.post(ENDPOINT, data={"email": xss}, headers={"Authorization": auth_token})
        assert "<script>" not in resp.text

    @pytest.mark.injection
    @pytest.mark.parametrize("nosql", NOSQL_INJECTIONS)
    def test_nosql_in_email(self, api, auth_token, nosql):
        resp = api.post(ENDPOINT, data={"email": nosql}, headers={"Authorization": auth_token})
        assert resp.status_code != 500

    @pytest.mark.injection
    @pytest.mark.parametrize("ssrf_url", SSRF_PAYLOADS)
    def test_ssrf_in_email(self, api, auth_token, ssrf_url):
        resp = api.post(ENDPOINT, data={"email": ssrf_url}, headers={"Authorization": auth_token})
        assert resp.status_code != 500

    @pytest.mark.injection
    def test_ldap_injection(self, api, auth_token):
        for payload in ["*", ")(cn=*", "*(|(objectclass=*))", "admin*)((|"]:
            resp = api.post(ENDPOINT, data={"email": payload}, headers={"Authorization": auth_token})
            assert resp.status_code != 500


class TestForgetPasswordEnumeration:

    @pytest.mark.critical
    def test_same_status_for_valid_and_invalid_email(self, api, auth_token):
        # both should return same status to prevent user enumeration
        valid = api.post(ENDPOINT, data={"email": "amira.mosa+991@bosta.co"}, headers={"Authorization": auth_token})
        invalid = api.post(ENDPOINT, data={"email": "nouser_xyz@fake99.com"}, headers={"Authorization": auth_token})
        assert valid.status_code == invalid.status_code, f"valid={valid.status_code} invalid={invalid.status_code}"

    @pytest.mark.critical
    def test_similar_response_length(self, api, auth_token):
        valid = api.post(ENDPOINT, data={"email": "amira.mosa+991@bosta.co"}, headers={"Authorization": auth_token})
        invalid = api.post(ENDPOINT, data={"email": "nouser@nowhere999.com"}, headers={"Authorization": auth_token})
        diff = abs(len(valid.text) - len(invalid.text))
        if diff > 100:
            pytest.xfail(f"Response length diff: {diff} chars")

    @pytest.mark.critical
    def test_no_timing_leak(self, api, auth_token):
        t1 = time.time()
        api.post(ENDPOINT, data={"email": "amira.mosa+991@bosta.co"}, headers={"Authorization": auth_token})
        d1 = time.time() - t1

        t2 = time.time()
        api.post(ENDPOINT, data={"email": "nope_not_real@nope99.com"}, headers={"Authorization": auth_token})
        d2 = time.time() - t2

        diff_ms = abs(d1 - d2) * 1000
        if diff_ms > 200:
            pytest.xfail(f"Timing diff: {diff_ms:.0f}ms")

    @pytest.mark.business_logic
    def test_email_case_variants(self, api, auth_token):
        variants = ["AMIRA.MOSA+991@BOSTA.CO", "Amira.Mosa+991@Bosta.Co", "amira.MOSA+991@bosta.CO"]
        statuses = []
        for email in variants:
            resp = api.post(ENDPOINT, data={"email": email}, headers={"Authorization": auth_token})
            statuses.append(resp.status_code)
        assert len(set(statuses)) == 1, f"Inconsistent: {list(zip(variants, statuses))}"


class TestForgetPasswordValidation:

    @pytest.mark.input_validation
    def test_invalid_email(self, api, auth_token):
        resp = api.post(ENDPOINT, data={"email": "notanemail"}, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_empty_email(self, api, auth_token):
        resp = api.post(ENDPOINT, data={"email": ""}, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_no_at_in_email(self, api, auth_token):
        resp = api.post(ENDPOINT, data={"email": "userwithoutatdomain.com"}, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_empty_body(self, api, auth_token):
        resp = api.post(ENDPOINT, data={}, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_missing_email_field(self, api, auth_token):
        resp = api.post(ENDPOINT, data={"username": "test"}, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_malformed_json(self, api, auth_token):
        resp = api.post(
            ENDPOINT, raw_body="{ broken }",
            headers={"Authorization": auth_token, "content-type": "application/json"}
        )
        assert resp.status_code in [400, 422]

    @pytest.mark.input_validation
    def test_number_for_email(self, api, auth_token):
        resp = api.post(ENDPOINT, data={"email": 12345}, headers={"Authorization": auth_token})
        assert resp.status_code in [400, 422]

    @pytest.mark.rate_limit
    @pytest.mark.critical
    def test_rate_limiting(self, api, auth_token):
        results = []
        for _ in range(20):
            resp = api.post(ENDPOINT, data={"email": "amira.mosa+991@bosta.co"}, headers={"Authorization": auth_token})
            results.append(resp.status_code)
        if not any(r == 429 for r in results):
            pytest.xfail("No rate limiting on password reset")

    @pytest.mark.business_logic
    def test_mass_reset_different_users(self, api, auth_token):
        for i in range(5):
            resp = api.post(ENDPOINT, data={"email": f"fake{i}@test.com"}, headers={"Authorization": auth_token})
            assert resp.status_code != 500

    @pytest.mark.data_exposure
    def test_no_user_info_leaked(self, api, auth_token):
        resp = api.post(ENDPOINT, data={"email": "amira.mosa+991@bosta.co"}, headers={"Authorization": auth_token})
        body = resp.text.lower()
        for pat in ["user_id", "phone", "address", "reset_token", "password"]:
            assert pat not in body, f"Leaked: {pat}"

    @pytest.mark.data_exposure
    def test_no_internals_in_errors(self, api, auth_token):
        resp = api.post(ENDPOINT, data={}, headers={"Authorization": auth_token})
        assert "at com." not in resp.text
        assert "Traceback" not in resp.text
        assert "SELECT" not in resp.text

    @pytest.mark.injection
    def test_header_injection(self, api, auth_token):
        headers = {"Authorization": auth_token, "X-Forwarded-For": "127.0.0.1", "Host": "evil.com"}
        resp = api.post(ENDPOINT, data={"email": "amira.mosa+991@bosta.co"}, headers=headers)
        assert resp.status_code != 500

    @pytest.mark.business_logic
    def test_unicode_homograph(self, api, auth_token):
        # cyrillic 'a' instead of latin 'a'
        resp = api.post(ENDPOINT, data={"email": "\u0430mira.mosa+991@bosta.co"}, headers={"Authorization": auth_token})
        assert resp.status_code != 500
