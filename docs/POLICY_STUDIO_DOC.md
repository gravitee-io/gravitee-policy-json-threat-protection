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


