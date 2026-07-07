# Control Validation — Password Policy Enforcement

## Control
Domain password policy (Default Domain Policy):
- Minimum length: 14 characters
- Complexity: enabled
- Password history: 24

## Test
During service-account provisioning, an account creation was attempted
with a 10-character password ("Summer2024").

## Result
Active Directory **rejected** the account creation:
> "The password does not meet the length, complexity, or history
> requirement of the domain."

## Conclusion
The password baseline is actively enforced at the directory level, not
merely configured. A compliant 14-character password was required before
the account could be created — confirming the control functions as designed.

![Policy](../Screenshots/password-policy.png)
![Rejection](../Screenshots/password-policy-rejection.png)