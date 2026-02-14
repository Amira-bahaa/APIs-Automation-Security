import os
import pytest
import logging
from framework.client import APIClient
from framework.token_utils import refresh_bank_info_token
from framework.ai_analyzer import ai_analyzer

logger = logging.getLogger(__name__)

BASE_URL = os.getenv("BASE_URL", "https://stg-app.bosta.co/api/v2")
AUTH_TOKEN = os.getenv(
    "AUTH_TOKEN",
    "bca27763f5f30353ba0ee3d2ebd8951994f5016e269bbd781798e2884274d631"
)
DEVICE_ID = os.getenv("DEVICE_ID", "01JV70TKSFGV9Z1QWEYV3N5APC")
DEVICE_FINGERPRINT = os.getenv("DEVICE_FINGERPRINT", "1hgtilh")

COMMON_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "en",
    "content-type": "application/json",
    "origin": "https://stg-business.bosta.co",
    "referer": "https://stg-business.bosta.co/",
    "x-device-id": DEVICE_ID,
    "x-device-fingerprint": DEVICE_FINGERPRINT,
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/137.0.0.0 Safari/537.36"
    ),
}


@pytest.fixture(scope="session")
def api(request):
    return APIClient(base_url=BASE_URL, default_headers=COMMON_HEADERS)


@pytest.fixture(scope="session")
def auth_token():
    return AUTH_TOKEN


@pytest.fixture(scope="session")
def bank_token():
    env_token = os.getenv("BANK_INFO_AUTH_TOKEN")
    if env_token:
        return env_token

    fresh = refresh_bank_info_token(BASE_URL)
    if fresh:
        return fresh

    logger.warning("Using fallback bank token - might be expired")
    return AUTH_TOKEN


@pytest.fixture(scope="session")
def ai():
    return ai_analyzer


@pytest.fixture
def valid_pickup_payload():
    return {
        "businessLocationId": "MFqXsoFhxO",
        "contactPerson": {
            "id": "sCFBrHGi",
            "name": "test_name",
            "email": "amira.mosa+991@bosta.co",
            "phone": "+201055592829",
        },
        "scheduledDate": "2025-12-30",
        "numberOfParcels": "3",
        "hasBigItems": False,
        "repeatedData": {"repeatedType": "One Time"},
        "creationSrc": "Web",
    }


@pytest.fixture
def valid_bank_payload():
    return {
        "bankInfo": {
            "beneficiaryName": "test name",
            "bankName": "NBG",
            "accountNumber": "123",
            "ibanNumber": "EG1234567890123456789012",
        },
        "paymentInfoOtp": "123",
    }


@pytest.fixture
def valid_forget_password_payload():
    return {"email": "amira.mosa+991@bosta.co"}
