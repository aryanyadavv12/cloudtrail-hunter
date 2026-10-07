"""Optional AWS CloudTrail integration.

The offline CLI does not require AWS credentials. This module is used when
users want to retrieve recent CloudTrail events through boto3.
"""

def lookup_recent_events(region=None, profile=None, lookup_attributes=None, max_results=50):
    import boto3
    session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    client = session.client("cloudtrail")
    kwargs = {"MaxResults": max_results}
    if lookup_attributes:
        kwargs["LookupAttributes"] = lookup_attributes
    paginator = client.get_paginator("lookup_events")
    events = []
    for page in paginator.paginate(**kwargs):
        for item in page.get("Events", []):
            events.append(item)
        if len(events) >= max_results:
            break
    return events[:max_results]
