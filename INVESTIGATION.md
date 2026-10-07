# Investigation Guide

When an alert fires, follow a repeatable SOC workflow:

1. **Validate the event:** confirm timestamp, AWS region, event name and event ID.
2. **Identify the principal:** review the IAM ARN, user, role and account context.
3. **Check source:** examine source IP and user agent; compare with expected administrator activity.
4. **Inspect request parameters:** determine what resource or policy was changed.
5. **Correlate:** search nearby CloudTrail events for related IAM, S3 or CloudTrail changes.
6. **Assess impact:** identify privilege changes, exposed data paths, or disabled logging.
7. **Contain when authorized:** revoke suspicious access, restore secure policy/logging configuration, and rotate affected credentials as appropriate.
8. **Document:** record evidence, timeline, scope, actions and final disposition.

For portfolio demonstrations, explain the reasoning rather than claiming that a single event proves compromise.
