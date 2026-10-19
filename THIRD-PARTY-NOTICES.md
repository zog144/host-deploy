# Third-party notices — host-deploy development source

This repository provides first-party Zog source, service-unit templates and
documentation under BSD-3-Clause OR GPL-3.0-only. See LICENSE and LICENSES/.
This is a development source grant, not a license to data, private host
credentials, separate upstream code, or downloaded system images.

Host-deploy declares the separately installed runtime dependency
`boto3>=1.34,<2` and its transitive requirements (including botocore,
s3transfer and others resolved at installation). These independent packages
retain their own upstream copyright and licensing; public source commits do not
bundle their wheel/sdist bytes or assert complete combined-binary notices.

Other Zog programs (root-control, box-control, image-build, host-identify,
host-discover and host-install) are referenced as separate externally selected
components with independently verified exact source revisions. Historical pins
from the prior private repositories cannot be reused without the new public
source-compatibility review.

At runtime this tool can provision EC2, submit SSM jobs, interact with S3 and
send authorized gateway SQS messages. Such operations may use separately
licensed distributions, machine images, and content-addressed build inputs.
No remotely acquired artifacts, live cloud state, compiled rootfs or public
binary distribution is incorporated by the source-only grant.
