import pytest

from portal.integration_secrets import (
    IntegrationSecretError,
    decrypt_integration_secret,
    encrypt_integration_secret,
)


def test_integration_secret_is_encrypted_and_purpose_separated():
    ciphertext = encrypt_integration_secret(
        "token-value", "application-secret", purpose="netbox-api-token"
    )
    assert "token-value" not in ciphertext
    assert (
        decrypt_integration_secret(
            ciphertext, "application-secret", purpose="netbox-api-token"
        )
        == "token-value"
    )
    with pytest.raises(IntegrationSecretError):
        decrypt_integration_secret(
            ciphertext, "application-secret", purpose="proxmox-token-secret"
        )
