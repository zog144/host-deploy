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



V3_SCHEMA = "zog-graphical-trust-broker-disabled-install-v3"
V3_FIELDS = (FIELDS - {"root_source_revision"}) | {
    "root_source_sha256", "installation_scope_sha256",
    "registry_sha256", "storage_commit_sha256",
}


def validate_disabled_v3_selection(
    manifest, *, actual_modules, installed_root_modules,
    service, socket_unit, installation_storage_record, storage_commit,
):
    """Proposed exact-byte v3 install only; never accepts mounted S3/IPC/IAM.

    Root modules and broker modules are installed-byte inputs of an independent
    installer, not a gateway manifest. The selected native root constructor
    must independently verify signed registry, grant, external anchor and
    installer-signed storage commit before using any read-only session.
    """
    from zog.root_control import graphical_installation_storage_authority as root
    from zog.root_control import graphical_task_c_trust_authority as authority
    from zog.root_control import graphical_operation_owner_source as op

    if (type(manifest) is not dict or set(manifest) != V3_FIELDS
            or manifest.get("schema") != V3_SCHEMA
            or type(actual_modules) is not dict
            or set(actual_modules) != SOURCES
            or type(installed_root_modules) is not dict
            or set(installed_root_modules) != set(authority.ROOT_V3_SOURCES)
            or any(type(v) is not bytes or not v
                   for v in list(actual_modules.values()) +
                             list(installed_root_modules.values()))
            or any(not trust.v2.match(manifest.get(k),trust.v2.SHA) for k in
                   ("root_source_sha256","installation_scope_sha256",
                    "registry_sha256","storage_commit_sha256",
                    "original_checkpoint_sha256",
                    "source_modules_sha256","service_sha256","socket_sha256",
                    "owner_observation_public_sha256",
                    "broker_signer_public_sha256",
                    "installed_gateway_source_sha256",
                    "gateway_executable_sha256","scope_sha256"))
            or any(not trust.v2.match(manifest.get(k),trust.v2.H64)
                   for k in ("host_id","installation_id","state_volume_id"))
            or type(service) is not bytes or type(socket_unit) is not bytes
            or manifest.get("status") != "NOT_ACTIVATED"
            or any(manifest.get(k) is not False for k in (
                "socket_enabled","service_enabled","broker_admitted",
                "original_authority_admitted")):
        hold()
    owner_sha = sha(b"".join(
        name.encode("ascii")+b"\0"+installed_root_modules[name]+b"\0"
        for name in sorted(authority.ROOT_V3_SOURCES)))
    broker_sha = sha(b"".join(
        name.encode("ascii")+b"\0"+actual_modules[name]+b"\0"
        for name in sorted(SOURCES)))
    if (owner_sha != manifest["root_source_sha256"]
            or broker_sha != manifest["source_modules_sha256"]
            or broker_sha != manifest["installed_gateway_source_sha256"]
            or sha(service) != manifest["service_sha256"]
            or sha(socket_unit) != manifest["socket_sha256"]):
        hold()
    src=installation_storage_record
    if (type(src) is not dict or set(src)!=root.AUTHORITY_KEYS
            or src.get("schema") != root.AUTHORITY_SCHEMA
            or src.get("mode") != root.SOURCE_MODE
            or src["installation_scope_sha256"] !=
                manifest["installation_scope_sha256"]
            or src["registry_sha256"] != manifest["registry_sha256"]
            or src["checkpoint_reader_role_arn"] !=
                manifest["readonly_checkpoint_role_arn"]
            or src["checkpoint_writer_role_arn"] !=
                manifest["owner_checkpoint_write_role_arn"]
            or sha(op.canonical(src)) != manifest["original_checkpoint_sha256"]
            or type(storage_commit) is not dict
            or sha(op.canonical(storage_commit)) !=
                manifest["storage_commit_sha256"]):
        hold()
    if (not all(type(manifest.get(k)) is str and ROLE.fullmatch(manifest[k])
                for k in ("readonly_checkpoint_role_arn","owner_ssm_role_arn",
                          "owner_checkpoint_write_role_arn"))
            or len({manifest["readonly_checkpoint_role_arn"],
                    manifest["owner_ssm_role_arn"],
                    manifest["owner_checkpoint_write_role_arn"]}) != 3
            or type(manifest.get("gateway_uid")) is not int
            or manifest["gateway_uid"] < 1000
            or type(manifest.get("gateway_gid")) is not int
            or manifest["gateway_gid"] <= 0):
        hold()
    try:
        text=service.decode("utf-8")
        sock=socket_unit.decode("utf-8")
    except UnicodeError:
        hold()
    units=text.split("[Service]",1)
    if (len(units)!=2 or "[Install]" in text or "[Install]" in sock or
            "ListenStream=" + daemon.SOCKET not in sock.splitlines() or
            "SocketMode=0660" not in sock.splitlines() or
            "Accept=no" not in sock.splitlines() or
            "NoNewPrivileges=yes" not in units[1].splitlines() or
            "CapabilityBoundingSet=" not in units[1].splitlines() or
            "RequiresMountsFor=/var/lib/zog-graphical-owner-ledger"
                not in units[0].splitlines() or
            "RequiresMountsFor=/var/lib/zog-graphical-owner-authority"
                not in units[0].splitlines() or
            any(x.startswith("RequiresMountsFor=")
                for x in units[1].splitlines()) or
            "ReadOnlyPaths=/var/lib/zog-graphical-owner-authority"
                not in units[1].splitlines() or
            "LoadCredential=read-only-checkpoint.json:" not in text or
            "LoadCredential=broker-private.key:" not in text or
            any(x in text for x in (
                "LoadCredential=aws-session.json",
                "LoadCredential=checkpoint-session.json",
                "ExecStartPost=", "WantedBy=")) or
            "ssm:SendCommand" in text):
        hold()
    return {
        "status":"V3_SOURCE_SELECTION_DISABLED",
        "exact_root_module_sha256":owner_sha,
        "exact_broker_module_sha256":broker_sha,
        "registry_genesis_verified_native":False,
        "external_anchor_verified_native":False,
        "read_only_role_verified_native":False,
        "socket_enabled":False,
        "broker_admitted":False,
        "ssm_authorized":False,
    }
