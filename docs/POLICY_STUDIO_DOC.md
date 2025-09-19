## Overview
You can use this policy to validate a JSON request body by specifying limits for various JSON structures (such as arrays, field names and string values).
When an invalid request is detected (meaning the limit is reached), the request will be considered a threat and rejected with a 400 BAD REQUEST.


