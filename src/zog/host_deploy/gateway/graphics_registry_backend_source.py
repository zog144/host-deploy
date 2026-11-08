"""Task C registry backend-bound mapping source review; never native admission.

host-install v2 verifies a registrar signature and equality against *supplied*
observation fields. That proves the signed record's syntax and provenance
relative to supplied inputs, NOT live kernel backing, mountinfo, retained
directory fd, actual marker bytes, installed identity or external S3 anchor.

This pure review deliberately cannot turn that result into an owner/broker
authority. A separate protected per-invocation native observation provider,
authenticated against installed wheel/units and selected Host, is REQUIRED
before any live integration can return an admission value.
"""
from .graphics_owner_trust_history import TrustUnavailable

SCHEMA = "zog-graphical-registry-backend-source-review-v1"
HOST_INSTALL_SOURCE = "24376bd784b7efcc1e393188f792c41685e75f79"
NATIVE_BACKEND_OBSERVATION_PROVIDER_INSTALLED = False

def review_signed_mapping(*, signed_mapping, legacy, registered_installation,
                          observation, backend, pinned_registrar_public,
                          pinned_registry_public):
    """Cross-owner source review ONLY; signature/booleans never grant authority.

    All parameters are untrusted test/review inputs. The installed owner
    MUST NOT call this function as a replacement for a native observation.
    """
    from zog.host_install import graphical_registry_identity_mapping_v2 as v2
    from zog.host_install.graphical_readonly_trust_broker_install import (
        BrokerInstallHeld)
    try:
        result = v2.verify_signed(
            signed_mapping=signed_mapping, legacy=legacy,
            registered_installation=registered_installation,
            observation=observation, backend=backend,
            pinned_registrar_public=pinned_registrar_public,
            pinned_registry_public=pinned_registry_public)
    except (BrokerInstallHeld, KeyError, TypeError, ValueError) as exc:
        raise TrustUnavailable("registry backend mapping source rejected") from exc
    if (type(result) is not dict
            or result.get("status") != "BACKEND_BOUND_MAPPING_SOURCE_VERIFIED_ONLY"
            or result.get("backend") != backend
            or result.get("native_accepted") is not False
            or result.get("checkpoint_authorized") is not False
            or result.get("broker_admission") is not False
            or result.get("ssm_authorized") is not False):
        raise TrustUnavailable("source mapping cannot supply native authority")
    return {
        "schema": SCHEMA,
        "backend": backend,
        "host_install_source": HOST_INSTALL_SOURCE,
        "source_mapping_verified": True,
        "native_accepted": False,
        "broker_admission": False,
        "ssm_authorized": False,
    }


def require_native_backend_observation(*_args, **_kwargs):
    """No caller-supplied signed mapping or verification flag is an owner grant."""
    raise TrustUnavailable(
        "protected backend-bound per-invocation observation not installed")
