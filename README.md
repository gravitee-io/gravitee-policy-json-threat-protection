
<!-- GENERATED CODE - DO NOT ALTER THIS OR THE FOLLOWING LINES -->
# JSON Threat Protection

[![Gravitee.io](https://img.shields.io/static/v1?label=Available%20at&message=Gravitee.io&color=1EC9D2)](https://download.gravitee.io/#graviteeio-apim/plugins/policies/gravitee-policy-json-threat-protection/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/blob/master/LICENSE.txt)
[![Releases](https://img.shields.io/badge/semantic--release-conventional%20commits-e10079?logo=semantic-release)](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/releases)
[![CircleCI](https://circleci.com/gh/gravitee-io/gravitee-policy-json-threat-protection.svg?style=svg)](https://circleci.com/gh/gravitee-io/gravitee-policy-json-threat-protection)

## Overview
You can use this policy to validate a JSON request body by specifying limits for various JSON structures (such as arrays, field names and string values).
When an invalid request is detected (meaning the limit is reached), the request will be considered a threat and rejected with a 400 BAD REQUEST.



## Errors
These templates are defined at the API level, in the "Entrypoint" section for v4 APIs, or in "Response Templates" for v2 APIs.
The error keys sent by this policy are as follows:

| Key |
| ---  |
| JSON_THREAT_DETECTED |
| JSON_THREAT_MAX_DEPTH |
| JSON_THREAT_MAX_ENTRIES |
| JSON_THREAT_MAX_NAME_LENGTH |
| JSON_THREAT_MAX_VALUE_LENGTH |
| JSON_MAX_ARRAY_SIZE |



## Phases
The `json-threat-protection` policy can be applied to the following API types and flow phases.

### Compatible API types

* `PROXY`
* `MESSAGE`

### Supported flow phases:

* Request

## Compatibility matrix
Strikethrough text indicates that a version is deprecated.

| Plugin version| APIM| Java version |
| --- | --- | ---  |
|3.x|4.7.x to latest|21 |
|2.x|4.x|17 |
|1.x|3.x|8 |


## Configuration options


#### 
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| Enforce JSON payload<br>`enforceJson`| boolean|  | `true`| When it’s activated, only JSON content is accepted|
| Maximum json array size<br>`maxArraySize`| integer| ✅| `100`| Maximum number of elements allowed in an array. (-1 to specify no limit)|
| Maximum json depth<br>`maxDepth`| integer| ✅| `100`| Maximum depth of json structure. Example: <code>{ "a":{ "b":{ "c":true }}}</code>, json has a depth of 3. (-1 to specify no limit)|
| Maximum json object entries<br>`maxEntries`| integer| ✅| `100`| Maximum number of entries allowed in an json object. Example: <code>{ "a":{ "b":1, "c":2, "d":3 }}</code>, "a" has 3 entries. (-1 to specify no limit)|
| Maximum json field name length<br>`maxNameLength`| integer| ✅| `100`| Maximum string length allowed for a json property name. (-1 to specify no limit)|
| Maximum json field value length<br>`maxValueLength`| integer| ✅| `100`| Maximum string length allowed for a json property value. (-1 to specify no limit)|
| Prevent duplicate key<br>`preventDuplicateKey`| boolean|  | `true`| If false, accept duplicate key|




## Examples

*Default configuration*
```json
{
  "api": {
    "definitionVersion": "V4",
    "type": "PROXY",
    "name": "JSON Threat Protection example API",
    "flows": [
      {
        "name": "Common Flow",
        "enabled": true,
        "selectors": [
          {
            "type": "HTTP",
            "path": "/",
            "pathOperator": "STARTS_WITH"
          }
        ],
        "response": [
          {
            "name": "JSON Threat Protection",
            "enabled": true,
            "policy": "json-threat-protection",
            "configuration":
              {
                  "maxEntries": 100,
                  "maxArraySize": 100,
                  "maxDepth": 100,
                  "maxNameLength": 100,
                  "maxValueLength": 500,
                  "preventDuplicateKey": true
              }
          }
        ]
      }
    ]
  }
}

```


## Changelog

### [3.0.0](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/2.1.1...3.0.0) (2026-09-24)


* chore(deps)!: move to the gravitee orb 5 and parent 23 ([23dd040](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/23dd040fd03f2caeb894e096ec7528f27a3a1f57))


##### BREAKING CHANGES

* the artifact is now compiled for Java 21, up from Java 17, and
requires a Java 21 runtime or later.

https://gravitee.atlassian.net/browse/BX-403

#### [2.1.1](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/2.1.0...2.1.1) (2026-04-23)


##### Bug Fixes

* make jsonFactory instance-scoped to prevent duplicate-key setting race condition ([#39](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/issues/39)) ([dcec1e2](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/dcec1e28473023cc36a21161a835ed15534a36a0))

### [2.1.0](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/2.0.0...2.1.0) (2025-10-14)


##### Features

* add new param to reject not JSON ([9c97531](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/9c975316df9c04e0fd64e488aed9e448660cfe1c))

### [2.0.0](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.4.0...2.0.0) (2025-09-24)


##### Bug Fixes

* lint ([a7bd8eb](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/a7bd8ebb3ec8aef32e6638cd742094733bccfb56))


##### chore

* bump versions ([719ed8f](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/719ed8f5216d588236f3fdae1103921a2fff9a46))


##### Features

* add setup to allow duplicate key ([56a6a0b](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/56a6a0bc2ff11adb49e995789090ac4b19eaf7dc))
* create integration tests ([5406abd](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/5406abde09d0a2e57de29ec95b95ecf441750199))


##### BREAKING CHANGES

* requier java 17

### [1.4.0](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.3.4...1.4.0) (2023-12-19)


##### Features

* enable policy on REQUEST phase for proxy and message APIs ([8b383dc](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/8b383dcbe32052b3d9ae6865ca5deabc58429649)), closes [gravitee-io/issues#9430](https://github.com/gravitee-io/issues/issues/9430)

#### [1.3.4](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.3.3...1.3.4) (2023-07-20)


##### Bug Fixes

* update policy description ([d784717](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/d78471710e1a8412df2d013868b3396347caf482))

#### [1.3.3](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.3.2...1.3.3) (2022-04-28)


##### Bug Fixes

* stop propagating request to backend if not valid ([4880ae8](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/4880ae861d97d5e4dab46d43944c800e917f3132))

#### [1.2.3](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.2.2...1.2.3) (2022-03-28)


##### Bug Fixes

* stop propagating request to backend if not valid ([4880ae8](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/4880ae861d97d5e4dab46d43944c800e917f3132))

#### [1.3.2](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.3.1...1.3.2) (2022-03-28)


##### Bug Fixes

* stop propagating request to backend if not valid ([d3dd683](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/d3dd683e016e44200e332c68829e1b5dc80f767a))

#### [1.3.1](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.3.0...1.3.1) (2022-01-24)


##### Bug Fixes

* **array-size:** properly check array size ([fab14ba](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/fab14ba776cf4077d38afdfaeaa53f51dcf6ee19)), closes [gravitee-io/issues#6050](https://github.com/gravitee-io/issues/issues/6050)
* threat protection policies: unable to adjust default values ([ef1f62e](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/ef1f62e65ccbeca3ccd6ed9a9489afbaca1dedb6)), closes [gravitee-io/issues#5982](https://github.com/gravitee-io/issues/issues/5982)

### [1.3.0](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/compare/1.2.0...1.3.0) (2022-01-24)


##### Features

* **headers:** Internal rework and introduce HTTP Headers API ([23095aa](https://github.com/gravitee-io/gravitee-policy-json-threat-protection/commit/23095aab51973e1ad56b9491878ed3a5c2947703)), closes [gravitee-io/issues#6772](https://github.com/gravitee-io/issues/issues/6772)

