import base64
import binascii
import hashlib
import json
import os
from typing import Any


SIGNUP_CONFIRMATION_TRIGGERS = {
    "PostConfirmation_ConfirmSignUp",
    "PostConfirmation_AdminConfirmSignUp",
}
POST_AUTHENTICATION_TRIGGER = "PostAuthentication_Authentication"
IGNORED_TRIGGERS = {
    "PostConfirmation_ConfirmForgotPassword",
}
SECRET_KEY_FRAGMENTS = (
    "secret",
    "token",
    "password",
    "credential",
    "privatekey",
    "private_key",
    "apikey",
    "api_key",
)
SECRET_VALUE_MARKERS = (
    "-----BEGIN ",
    "AKIA",
    "ASIA",
    "xoxb-",
    "ghp_",
    "gho_",
)


class AuthLifecycleConfigError(ValueError):
    pass


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    profiles = _load_profiles()
    trigger_source = _event_string(event, "triggerSource")

    if trigger_source in IGNORED_TRIGGERS:
        _log("INFO", "Ignored Cognito lifecycle trigger", triggerSource=trigger_source)
        return event

    if trigger_source not in SIGNUP_CONFIRMATION_TRIGGERS and trigger_source != POST_AUTHENTICATION_TRIGGER:
        _log("INFO", "Unsupported Cognito lifecycle trigger", triggerSource=trigger_source)
        return event

    profile = _matching_profile(event, profiles)
    if profile is None:
        raise AuthLifecycleConfigError("No lifecycle profile matches this Cognito event")

    if not profile.get("enabled", True):
        _log("INFO", "Lifecycle profile disabled", domain=str(profile.get("domain") or ""), authProfileId=str(profile.get("authProfileId") or ""))
        return event

    if trigger_source == POST_AUTHENTICATION_TRIGGER and profile.get("repairOnPostAuthentication") is not True:
        _log("INFO", "Post-auth repair disabled", domain=str(profile.get("domain") or ""), authProfileId=str(profile.get("authProfileId") or ""))
        return event

    _apply_profile(event, profile, trigger_source)
    return event


def _load_profiles() -> list[dict[str, Any]]:
    raw_config = _profile_config_json()
    if not raw_config:
        raise AuthLifecycleConfigError("PROFILE_CONFIG_JSON_BASE64 or PROFILE_CONFIG_JSON is required")
    try:
        config = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        raise AuthLifecycleConfigError("Profile config must be valid JSON") from exc

    _reject_secret_like_config(config)
    profiles = config.get("profiles") if isinstance(config, dict) else None
    if not isinstance(profiles, list):
        raise AuthLifecycleConfigError("Profile config profiles must be a list")

    normalized_profiles: list[dict[str, Any]] = []
    for index, profile in enumerate(profiles):
        if not isinstance(profile, dict):
            raise AuthLifecycleConfigError(f"Profile {index} must be an object")
        normalized_profiles.append(_validate_profile(profile, index))
    return normalized_profiles


def _profile_config_json() -> str:
    raw_base64_config = os.environ.get("PROFILE_CONFIG_JSON_BASE64", "").strip()
    if raw_base64_config:
        try:
            return base64.b64decode(raw_base64_config, validate=True).decode("utf-8").strip()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise AuthLifecycleConfigError("PROFILE_CONFIG_JSON_BASE64 must be valid base64-encoded UTF-8 JSON") from exc
    return os.environ.get("PROFILE_CONFIG_JSON", "").strip()


def _validate_profile(profile: dict[str, Any], index: int) -> dict[str, Any]:
    normalized = dict(profile)
    for key in ("domain", "authProfileId", "userPoolId", "tenantId"):
        if not _clean_string(normalized.get(key)):
            raise AuthLifecycleConfigError(f"Profile {index} requires {key}")

    normalized["tenantClaim"] = _clean_string(normalized.get("tenantClaim") or "custom:tenant_id")
    if not normalized["tenantClaim"].startswith("custom:"):
        raise AuthLifecycleConfigError(f"Profile {index} tenantClaim must be a custom Cognito attribute")

    normalized["clientIds"] = _string_list(normalized.get("clientIds"))
    if not normalized["clientIds"]:
        raise AuthLifecycleConfigError(f"Profile {index} requires at least one clientId")

    normalized["allowedGroups"] = _string_list(normalized.get("allowedGroups"))
    normalized["defaultGroups"] = _string_list(normalized.get("defaultGroups"))
    if any(group not in normalized["allowedGroups"] for group in normalized["defaultGroups"]):
        raise AuthLifecycleConfigError(f"Profile {index} defaultGroups must be allowedGroups")

    normalized["attributes"] = _profile_attributes(normalized, index)
    normalized["groupAssignmentMode"] = _clean_string(normalized.get("groupAssignmentMode") or "always")
    if normalized["groupAssignmentMode"] not in {"always", "ifNoAllowedGroup"}:
        raise AuthLifecycleConfigError(f"Profile {index} groupAssignmentMode is not supported")

    normalized["enabled"] = normalized.get("enabled", True) is True
    return normalized


def _profile_attributes(profile: dict[str, Any], index: int) -> dict[str, str]:
    attributes = _string_map(profile.get("attributes"), field_name="attributes")
    tenant_claim = _clean_string(profile["tenantClaim"])
    tenant_id = _clean_string(profile["tenantId"])

    for name in attributes:
        if not name.startswith("custom:"):
            raise AuthLifecycleConfigError(f"Profile {index} attributes must be custom Cognito attributes")

    if profile.get("setTenantClaim", True) is not False and tenant_claim:
        existing_tenant = attributes.get(tenant_claim)
        if existing_tenant and existing_tenant != tenant_id:
            raise AuthLifecycleConfigError(f"Profile {index} tenant attribute conflicts with tenantId")
        attributes = {tenant_claim: tenant_id, **{key: value for key, value in attributes.items() if key != tenant_claim}}

    return attributes


def _matching_profile(event: dict[str, Any], profiles: list[dict[str, Any]]) -> dict[str, Any] | None:
    user_pool_id = _event_string(event, "userPoolId")
    client_id = _event_nested_string(event, ("callerContext", "clientId"))
    matches = [
        profile
        for profile in profiles
        if profile["userPoolId"] == user_pool_id and client_id in profile["clientIds"]
    ]
    if len(matches) > 1:
        raise AuthLifecycleConfigError("Multiple lifecycle profiles match this Cognito event")
    return matches[0] if matches else None


def _apply_profile(event: dict[str, Any], profile: dict[str, Any], trigger_source: str) -> None:
    user_pool_id = _event_string(event, "userPoolId")
    username = _event_string(event, "userName")
    if not user_pool_id or not username:
        raise AuthLifecycleConfigError("Cognito lifecycle event requires userPoolId and userName")

    user_attributes = event.get("request", {}).get("userAttributes", {})
    if not isinstance(user_attributes, dict):
        user_attributes = {}

    cognito = _cognito_client()
    desired_attributes = [
        {"Name": name, "Value": value}
        for name, value in profile["attributes"].items()
        if user_attributes.get(name) != value
    ]
    if desired_attributes:
        cognito.admin_update_user_attributes(
            UserPoolId=user_pool_id,
            Username=username,
            UserAttributes=desired_attributes,
        )

    for group_name in _groups_to_add(cognito, user_pool_id, username, profile):
        cognito.admin_add_user_to_group(
            UserPoolId=user_pool_id,
            Username=username,
            GroupName=group_name,
        )

    _log(
        "INFO",
        "Applied Cognito lifecycle profile",
        triggerSource=trigger_source,
        domain=_clean_string(profile.get("domain")),
        authProfileId=_clean_string(profile.get("authProfileId")),
        userHash=_user_hash(username),
        groupCount=len(profile["defaultGroups"]),
        attributeCount=len(profile["attributes"]),
    )


def _groups_to_add(cognito: Any, user_pool_id: str, username: str, profile: dict[str, Any]) -> list[str]:
    default_groups = profile["defaultGroups"]
    if not default_groups:
        return []

    if profile["groupAssignmentMode"] == "always":
        return default_groups

    response = cognito.admin_list_groups_for_user(UserPoolId=user_pool_id, Username=username)
    existing_groups = {
        _clean_string(group.get("GroupName"))
        for group in response.get("Groups", [])
        if isinstance(group, dict)
    }
    if existing_groups & set(profile["allowedGroups"]):
        return []
    return default_groups


def _cognito_client() -> Any:
    import boto3  # Imported lazily so unit tests do not need boto3 installed.

    return boto3.client("cognito-idp")


def _reject_secret_like_config(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            key_compact = key_text.replace("-", "_").lower()
            if any(fragment in key_compact for fragment in SECRET_KEY_FRAGMENTS):
                raise AuthLifecycleConfigError(f"Secret-like config key is not allowed at {path}.{key_text}")
            _reject_secret_like_config(child, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_like_config(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if any(marker in value for marker in SECRET_VALUE_MARKERS):
            raise AuthLifecycleConfigError(f"Secret-like config value is not allowed at {path}")


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AuthLifecycleConfigError("Expected a list of strings")
    strings = []
    for item in value:
        item_string = _clean_string(item)
        if not item_string:
            raise AuthLifecycleConfigError("Lists must contain non-empty strings")
        strings.append(item_string)
    return strings


def _string_map(value: Any, *, field_name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AuthLifecycleConfigError(f"{field_name} must be an object")
    strings: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = _clean_string(raw_key)
        string_value = _clean_string(raw_value)
        if not key or not string_value:
            raise AuthLifecycleConfigError(f"{field_name} must contain non-empty string keys and values")
        strings[key] = string_value
    return strings


def _event_string(event: dict[str, Any], key: str) -> str:
    return _clean_string(event.get(key))


def _event_nested_string(event: dict[str, Any], keys: tuple[str, ...]) -> str:
    current: Any = event
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return _clean_string(current)


def _clean_string(value: Any) -> str:
    return str(value or "").strip()


def _user_hash(username: str) -> str:
    return hashlib.sha256(username.encode("utf-8")).hexdigest()[:12]


def _log(level: str, message: str, **fields: Any) -> None:
    configured = os.environ.get("LOG_LEVEL", "INFO").upper()
    levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
    if levels.get(level, 20) < levels.get(configured, 20):
        return
    print(json.dumps({"level": level, "message": message, **fields}, sort_keys=True))
