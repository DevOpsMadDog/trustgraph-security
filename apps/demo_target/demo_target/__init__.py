"""
DELIBERATELY VULNERABLE — for hackathon sandbox use only.

This mini-service mirrors the payments-platform topology in the seed threat
model and embeds the exact threats the planner expects to find:

  thr-001  JWT audience validation bypass         (auth-service)
  thr-002  MFA enrollment bypass via reset        (auth-service)
  thr-004  PAN leakage in error responses         (payments-api)
  thr-006  SSRF via webhook URL validation gap    (webhook-dispatcher)
  thr-007  Horizontal privilege escalation/IDOR   (admin-portal)
  thr-008  Admin portal session fixation          (admin-portal)

DO NOT EVER expose this on a real network.
"""
