"""Bounded, identity-bound systemd 252 StartTransientUnit job completion.

Subscribe and install the D-Bus match BEFORE StartTransientUnit. JobRemoved
may precede the method reply; cache that exact job result and correlate by
the returned OBJECT PATH and exact UNIT. No generic unit dispatch, retry,
blocking wait without a deadline or reliance on a job that systemd unloaded.
"""
import asyncio
import re

MAX_WAIT_SECONDS = 20
_JOB = re.compile(r"/org/freedesktop/systemd1/job/[1-9][0-9]*\Z")


class JobNotProven(RuntimeError):
    def __init__(self, status="uncertain"):
        super().__init__("protected PID1 job " + status)
        self.status = status


async def start_and_wait(bus, message, unit, *, on_ack=None,
                         timeout=MAX_WAIT_SECONDS):
    from dbus_next import Message, MessageType

    if (type(timeout) not in (int, float) or not 0 < timeout <= MAX_WAIT_SECONDS
            or type(unit) is not str or not unit.endswith(".service")):
        raise ValueError("invalid protected PID1 wait authority")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    received = {}
    arrived = asyncio.Event()
    trusted_sender = None

    def handler(msg):
        if (msg.message_type == MessageType.SIGNAL
                and msg.interface == "org.freedesktop.systemd1.Manager"
                and msg.member == "JobRemoved"
                and trusted_sender is not None
                and msg.sender == trusted_sender
                and msg.path == "/org/freedesktop/systemd1"
                and msg.signature == "uoss" and len(msg.body) == 4):
            _, path, name, result = msg.body
            if (type(path) is str and _JOB.fullmatch(path)
                    and name == unit):
                received[path] = result
                arrived.set()
        return False

    bus.add_message_handler(handler)

    async def call(msg):
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise JobNotProven("deadline-expired")
        try:
            reply = await asyncio.wait_for(bus.call(msg), remaining)
        except asyncio.TimeoutError:
            raise JobNotProven("method-timeout") from None
        if reply.message_type == MessageType.ERROR:
            raise JobNotProven("PID1-error-reply")
        return reply

    try:
        rule = ("type='signal',sender='org.freedesktop.systemd1',"
                "interface='org.freedesktop.systemd1.Manager',"
                "member='JobRemoved',path='/org/freedesktop/systemd1'")
        match = await call(Message(
            destination="org.freedesktop.DBus", path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus", member="AddMatch",
            signature="s", body=[rule]))
        if match.signature != "":
            raise JobNotProven("signal-match-unconfirmed")
        owner = await call(Message(
            destination="org.freedesktop.DBus", path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus", member="GetNameOwner",
            signature="s", body=["org.freedesktop.systemd1"]))
        if (owner.signature != "s" or len(owner.body) != 1
                or type(owner.body[0]) is not str
                or not re.fullmatch(r":[0-9]+(?:\.[0-9]+)+", owner.body[0])):
            raise JobNotProven("PID1-unique-sender-unconfirmed")
        trusted_sender = owner.body[0]
        subscribed = await call(Message(
            destination="org.freedesktop.systemd1",
            path="/org/freedesktop/systemd1",
            interface="org.freedesktop.systemd1.Manager",
            member="Subscribe"))
        if subscribed.signature != "":
            raise JobNotProven("subscription-unconfirmed")
        started = await call(message)
        if (started.signature != "o" or len(started.body) != 1
                or type(started.body[0]) is not str
                or not _JOB.fullmatch(started.body[0])):
            raise JobNotProven("uncertain-start-reply")
        job_path = started.body[0]
        # This callback must fsync the job identity before accepting a
        # completion. A lost ack remains a durable attempted-start marker.
        if on_ack is not None:
            on_ack(job_path)
        while job_path not in received:
            arrived.clear()
            if job_path in received:
                break
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise JobNotProven("completion-timeout")
            try:
                await asyncio.wait_for(arrived.wait(), remaining)
            except asyncio.TimeoutError:
                raise JobNotProven("completion-timeout") from None
        result = received[job_path]
        if result != "done":
            raise JobNotProven("failed-result-" + str(result)[:48])
        return {"job_path": job_path, "job_result": "done",
                "unit": unit, "method": "StartTransientUnit", "reload": False}
    finally:
        bus.remove_message_handler(handler)
