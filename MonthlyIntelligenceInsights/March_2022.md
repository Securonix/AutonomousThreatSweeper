# Okta breached by Lapsus$ Extortion Gang

### Activity 
```Potential Administrator Role Manipulation ```
#### Description 
This detects a group’s or user’s admin privilege grant events and can be used to audit the provisioning of admin privileges for groups and users. When fired, this event contains information about the type of admin privileges the group currently has and what entity sources the group. The group that is granted privileges can be an Okta-sourced group, an AD-sourced group, or an LDAP-sourced group or type of admin privileges the user currently has.
#### Omega UUID: CLO-OKT1-RUN
#### Spotter Query 6.3.1
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "group.privilege.grant" OR devicecustomstring4 = "user.account.privilege.grant")
```
#### Spotter Query 6.4
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "group.privilege.grant" OR customstring38 = "user.account.privilege.grant")
```

### Activity
```Attempt To Create Or Revoke Okta API Token ```
#### Description 
This detects an attempt to create an Okta API token that can be used for persistence in the organization’s network, create new users and notify security controls.
#### Omega UUID:CLO-OKT2-RUN
#### Spotter Query 6.3.1
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "system.api_token.create" OR devicecustomstring4 = "system.api_token.revoke")
```
#### Spotter Query 6.4
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "system.api_token.create" OR customstring38 = "system.api_token.revoke")
```
### Activity
```Attempt To Modify Okta Application ```
#### Description
This detects an attempt to modify the Okta application and change security controls.
#### Omega UUID: CLO-OKT3-RUN
#### Spotter Query 6.3.1
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "application.lifecycle.update" OR devicecustomstring4 = "application.lifecycle.delete" OR devicecustomstring4 = "application.lifecycle.deactivate")
```
#### Spotter Query 6.4
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "application.lifecycle.update" OR customstring38 = "application.lifecycle.delete" OR customstring38 = "application.lifecycle.deactivate")
```
### Activity
```Attempt To Modify Okta Sign-on Policy ```
#### Description
This detects an attempt to modify the Okta sign-on policy. An adversary can use this vector to change security controls.
#### Omega UUID: CLO-OKT4-RUN
#### Spotter Query 6.3.1
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "application.policy.sign_on.update" OR devicecustomstring4 = "application.policy.sign_on.rule.delete")
```
#### Spotter Query 6.4
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "application.policy.sign_on.update" OR customstring38 = "application.policy.sign_on.rule.delete")
```
### Activity
```Attempt To Modify Okta Multi-factor Authentication  ```
#### Description
This detects an attempt to modify the Okta MFA. An adversary can use this to change security controls.
#### Omega UUID: CLO-OKT5-RUN
#### Spotter Query 6.3.1
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "user.mfa.factor.deactivate" OR devicecustomstring4 = "user.mfa.factor.reset_all")
```
#### Spotter Query 6.4
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "user.mfa.factor.deactivate" OR customstring38 = "user.mfa.factor.reset_all")
```
### Activity
```Attempt To Modify Okta Network Zone  ```
#### Description
This detects an attempt to modify the Okta Network Zone. With this an adversary can  change security controls as needed.
#### Omega UUID: CLO-OKT6-RUN
#### Spotter Query 6.3.1
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "zone.deactivate" OR devicecustomstring4 = "zone.delete" OR devicecustomstring4 = "zone.remove_blacklist" OR devicecustomstring4 = "network_zone.rule.disabled")
```
#### Spotter Query 6.4
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "zone.deactivate" OR customstring38 = "zone.delete" OR customstring38 = "zone.remove_blacklist" OR customstring38 = "network_zone.rule.disabled")
```
### Activity
```Attempt To Modify Okta Policy``` 

#### Description
This detects an attempt to modify the Okta policy. An adversary can use this to change security controls.

#### Omega UUID: CLO-OKT7-RUN

#### Spotter Query 6.3.1:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "policy.lifecycle.update" OR devicecustomstring4 = "policy.lifecycle.delete")
```
#### Spotter Query 6.4:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "policy.lifecycle.update" OR customstring38 = "policy.lifecycle.delete")
```

### Activity 
```Attempt To Modify Okta Policy Rule ```

#### Description
This detects an attempt to modify Okta policy rules. An adversary can use this to change security controls.

#### Omega UUID: CLO-OKT8-RUN

#### Spotter Query 6.3.1:

```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "policy.rule.update" OR devicecustomstring4 = "policy.rule.delete" OR devicecustomstring4 = "policy.rule.deactivate")
```
#### Spotter Query 6.4:

```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "policy.rule.update" OR customstring38 = "policy.rule.delete" OR customstring38 = "policy.rule.deactivate")
```

### Activity 
```Potential Malicious Request Okta ```

#### Description
 This detects a malicious request from an IP that is identified by Okta ThreatInsight. It can be used to monitor and act on credential-based attacks (such as brute force, password spray) on your organization. 

#### Omega UUID: CLO-OKT9-RUN

#### Spotter Query 6.3.1:

```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND devicecustomstring4 = "security.threat.detected"
```
#### Spotter Query 6.4:

```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND customstring38 = "security.threat.detected"
```

### Activity
```Potential Unauthorized Access to Okta Application```

#### Description 
This detects unauthorized access to Okta.

#### Omega UUID: CLO-OKT10-RUN

#### Spotter Query 6.3.1:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND devicecustomstring4 = "app.generic.unauth_app_access_attempt"
```

#### Spotter Query 6.4:
```text 
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND customstring38 = "app.generic.unauth_app_access_attempt"
```

### Activity
```Potential Brute Force Attempt Okta ```

#### Description
This detects an Okta account lock event that indicates a brute force attack on the account.

#### Omega UUID: CLO-OKT11-RUN

#### Spotter Query 6.3.1:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND devicecustomstring4 = "user.account.lock"
```
#### Spotter Query 6.4:
```text 
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND customstring38 = "user.account.lock"
```

### Activity
```Potential Bypass Attempt Okta MFA``` 

#### Description
This detects attempts on an Okta login to bypass Okta multi-factor authentication.

#### Omega UUID: CLO-OKT12-RUN

#### Spotter Query 6.3.1:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND devicecustomstring4 = "user.mfa.attempt_bypass"
```
#### Spotter Query 6.4:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND customstring38 = "user.mfa.attempt_bypass"
```

### Activity
```Potential Denial of Service Okta ```

#### Description
This detects a potential DoS (denial of service) attack.

#### Omega UUID: CLO-OKT13-RUN

#### Spotter Query 6.3.1:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND (devicecustomstring4 = "application.integration.rate_limit_exceeded" OR devicecustomstring4 = "system.org.rate_limit.warning" OR devicecustomstring4 = "system.org.rate_limit.violation" OR devicecustomstring4 = "core.concurrency.org.limit.violation")
```
#### Spotter Query 6.4:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND ( customstring38 = "application.integration.rate_limit_exceeded" OR customstring38 = "system.org.rate_limit.warning" OR customstring38 = "system.org.rate_limit.violation" OR customstring38 = "core.concurrency.org.limit.violation")
```

### Activity
```Suspicious Activity On Account Okta ```

#### Description
This detects suspicious activity that is reported by an Okta user.

#### Omega UUID: CLO-OKT14-RUN

#### Spotter Query 6.3.1:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND devicecustomstring4 = "user.account.report_suspicious_activity_by_enduser"
```
#### Spotter Query 6.4:
```text
index=activity AND rg_functionality="Cloud Authentication / SSO / Single Sign-On" AND rg_vendor = "Okta" AND evicecustomstring4 = "user.account.report_suspicious_activity_by_enduser"
```








