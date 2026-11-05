"""Read-only graphical trust-broker disabled-install source selection.

This validator does not create authorities, install files, enable units, mint
public pins, or configure AWS. Host-install owns independent RECORD/STATE
attestation and explicit continuation of the original protected S3 tuple.
"""
import hashlib
import re

from . import graphics_owner_trust_daemon as daemon
from . import graphics_owner_trust_history as trust

SCHEMA = "zog-graphical-trust-broker-disabled-install-v1"
OWNER = "5ad7d5ed72d1b72edc767a658de28506791a74d4"
SOURCES = frozenset((
    "zog.host_deploy.gateway.graphics_owner_ipc",
    "zog.host_deploy.gateway.graphics_owner_observation_v2",
    "zog.host_deploy.gateway.graphics_owner_trust_history",
    "zog.host_deploy.gateway.graphics_owner_trust_service",
    "zog.host_deploy.gateway.graphics_owner_trust_daemon",
))
FINGERPRINTS = frozenset((
    "scope_sha256",
    "gateway_executable_sha256","original_checkpoint_sha256",
    "owner_observation_public_sha256","broker_signer_public_sha256",
    "installed_gateway_source_sha256",
))
FIELDS = frozenset((
    "schema","root_source_revision","gateway_source_revision",
    "host_id","installation_id","state_volume_id","scope_sha256",
    "gateway_executable_sha256","gateway_uid","gateway_gid",
    "gateway_cgroup","original_checkpoint_sha256",
    "owner_observation_public_sha256","broker_signer_public_sha256",
    "installed_gateway_source_sha256","readonly_checkpoint_role_arn",
    "owner_ssm_role_arn","owner_checkpoint_write_role_arn",
    "source_modules_sha256","service_sha256","socket_sha256",
    "runtime_python","status","socket_enabled","service_enabled",
    "broker_admitted","original_authority_admitted",
))
ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@-]{1,64}\Z")


class BrokerInstallHold(ValueError):
    pass


def hold():
    raise BrokerInstallHold("read-only graphical broker has no accepted native installation")


def sha(data):
    if type(data) is not bytes:
        hold()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def validate_disabled_selection(manifest, *, actual_modules, service, socket_unit,
                                original_checkpoint_record):
    """Review exact bytes with no I/O or side effects.

    Every actual module byte value comes from independently installed wheel
    RECORD/source validation; manifest is not itself trusted authority.
    """
    if (type(manifest) is not dict or set(manifest) != FIELDS
            or manifest["schema"] != SCHEMA
            or manifest["root_source_revision"] != OWNER
            or type(manifest["gateway_source_revision"]) is not str
            or re.fullmatch(r"[a-f0-9]{40}",manifest["gateway_source_revision"]) is None
            or type(actual_modules) is not dict
            or set(actual_modules) != SOURCES
            or any(type(v) is not bytes or not v for v in actual_modules.values())
            or type(service) is not bytes or type(socket_unit) is not bytes
            or any(not trust.v2.match(manifest[k],trust.v2.SHA)
                   for k in FINGERPRINTS)
            or any(not trust.v2.match(manifest[k],trust.v2.H64)
                   for k in ("host_id","installation_id","state_volume_id"))
            or type(manifest["gateway_uid"]) is not int
            or manifest["gateway_uid"] < 1000
            or type(manifest["gateway_gid"]) is not int
            or manifest["gateway_gid"] <= 0
            or type(manifest["gateway_cgroup"]) is not str
            or not manifest["gateway_cgroup"].startswith("/system.slice/")
            or not manifest["gateway_cgroup"].endswith(".service")
            or type(manifest["runtime_python"]) is not str
            or not manifest["runtime_python"].startswith("/")
            or manifest["status"] != "NOT_ACTIVATED"
            or any(manifest[k] is not False for k in (
                "socket_enabled","service_enabled","broker_admitted",
                "original_authority_admitted"))
            or not all(type(manifest[k]) is str and ROLE.fullmatch(manifest[k])
                       for k in ("readonly_checkpoint_role_arn",
                                 "owner_ssm_role_arn",
                                 "owner_checkpoint_write_role_arn"))
            or len({manifest["readonly_checkpoint_role_arn"],
                    manifest["owner_ssm_role_arn"],
                    manifest["owner_checkpoint_write_role_arn"]}) != 3):
        hold()
    if (sha(service) != manifest["service_sha256"]
            or sha(socket_unit) != manifest["socket_sha256"]
            or sha(b"".join(name.encode("ascii") + b"\0" +
                            actual_modules[name] + b"\0"
                            for name in sorted(SOURCES))) !=
               manifest["source_modules_sha256"]):
        hold()
    try:
        service_text = service.decode("utf-8")
        socket_text = socket_unit.decode("utf-8")
    except UnicodeError:
        hold()
    mandatory_service=(
        "User=root","Group=root","ProtectSystem=strict",
        "CapabilityBoundingSet=",
        "LoadCredential=read-only-checkpoint.json:/var/lib/zog-graphical-trust-credential-source/read-only-checkpoint.json",
        "LoadCredential=broker-private.key:/etc/zog/graphical-owner/trust-broker-private.key",
        "RequiresMountsFor=/var/lib/zog-graphical-owner-ledger",
        "Sockets=zog-graphical-trust.socket",
    )
    mandatory_socket=(
        "ListenStream=" + daemon.SOCKET,
        "SocketUser=root", "SocketGroup=zog-graphical-client",
        "SocketMode=0660","Accept=no",
        "Service=zog-graphical-trust.service",
        "FileDescriptorName=trust-history",
    )
    if (any(entry not in service_text.splitlines() for entry in mandatory_service)
            or any(entry not in socket_text.splitlines()
                   for entry in mandatory_socket)
            or any(line.startswith("[Install]") for line in
                   service_text.splitlines() + socket_text.splitlines())
            or any(s in service_text for s in (
                "aws-session.json", "checkpoint-session.json",
                "EnvironmentFile=", "ExecStartPost=", "WantedBy="))
            or any(s in socket_text for s in (
                "WantedBy=", "ListenSequentialPacket=", "Accept=yes"))
            or "graphics_owner_trust_daemon" not in service_text):
        hold()
    row=original_checkpoint_record
    if (type(row) is not dict or
            set(row) != {
                "schema","host_id","installation_id","state_volume_id",
                "checkpoint_account_id","checkpoint_region",
                "checkpoint_bucket","checkpoint_prefix",
                "checkpoint_scope_sha256","checkpoint_genesis_sha256",
                "checkpoint_role_arn","root_source_revision"}
            or row["schema"] != "zog-task-c-original-checkpoint-installation-v1"
            or row["root_source_revision"] != OWNER
            or row["host_id"] != manifest["host_id"]
            or row["installation_id"] != manifest["installation_id"]
            or row["state_volume_id"] != manifest["state_volume_id"]
            or row["checkpoint_scope_sha256"] != manifest["scope_sha256"]
            or row["checkpoint_role_arn"] !=
               manifest["owner_checkpoint_write_role_arn"]
            or sha(trust.canonical(row)) !=
               manifest["original_checkpoint_sha256"]):
        hold()
    # A review of given bytes is NEVER the independently protected anchor,
    # actual GetObject IAM readback, signed authority, or gateway IAM denial.
    return {"status":"SOURCE_SELECTION_DISABLED",
            "native_broker_installed":False,
            "authentic_operator_mapping_verified":False,
            "read_only_s3_role_verified":False,
            "gateway_ssm_denied":False}
