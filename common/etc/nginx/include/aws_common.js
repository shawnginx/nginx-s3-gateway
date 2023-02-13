/*
 *  Copyright 2023 F5, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

const mod_hmac = require('crypto');
const fs = require('fs');

/**
 * Flag indicating debug mode operation. If true, additional information
 * about signature generation will be logged.
 * @type {boolean}
 */
const DEBUG = parseBoolean(process.env['AWS_DEBUG']);

/**
 * Constant checksum for an empty HTTP body.
 * @type {string}
 */
const EMPTY_PAYLOAD_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/**
 * @type {string}
 */
const EC2_IMDS_TOKEN_ENDPOINT = 'http://169.254.169.254/latest/api/token';

const EC2_IMDS_SECURITY_CREDENTIALS_ENDPOINT = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';

/**
 * Constant base URI to fetch credentials together with the credentials relative URI, see
 * https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html for more details.
 * @type {string}
 */
const ECS_CREDENTIAL_BASE_URI = 'http://169.254.170.2';

/**
 * Constant defining the headers being signed.
 * @type {string}
 */
const DEFAULT_SIGNED_HEADERS = 'host;x-amz-content-sha256;x-amz-date';

/**
 * Constant defining the default role session name.
 * @type {string}
 */
const DEFAULT_ROLE_SESSION_NAME = 'nginx-aws-signature';

/**
 * The current moment as a timestamp. This timestamp will be used across
 * functions in order for there to be no variations in signatures.
 * @type {Date}
 */
const NOW = new Date();

/**
 * Creates a string containing the headers that need to be signed as part of v4
 * signature authentication.
 *
 * @param sessionToken {string|undefined} AWS session token if present
 * @returns {string} semicolon delimited string of the headers needed for signing
 */
function signedHeaders(sessionToken) {
    let headers = DEFAULT_SIGNED_HEADERS;
    if (sessionToken) {
        headers += ';x-amz-security-token';
    }
    return headers;
}

/**
 * Creates a canonical request that will later be signed
 *
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html | Creating a Canonical Request}
 * @param method {string} HTTP method
 * @param uri {string} URI associated with request
 * @param queryParams {string} query parameters associated with request
 * @param host {string} HTTP host header value
 * @param amzDatetime {string} ISO8601 timestamp string to sign request with
 * @returns {string} string with concatenated request parameters
 * @private
 */
function buildCanonicalRequest(method, uri, queryParams, host, amzDatetime, sessionToken) {
    let canonicalHeaders = 'host:' + host + '\n' +
        'x-amz-content-sha256:' + EMPTY_PAYLOAD_HASH + '\n' +
        'x-amz-date:' + amzDatetime + '\n';

    if (sessionToken) {
        canonicalHeaders += 'x-amz-security-token:' + sessionToken + '\n'
    }

    let canonicalRequest = method + '\n';
    canonicalRequest += uri + '\n';
    if (queryParams) {
        canonicalRequest += queryParams + '\n';
    }
    canonicalRequest += canonicalHeaders + '\n';
    canonicalRequest += signedHeaders(sessionToken) + '\n';
    canonicalRequest += EMPTY_PAYLOAD_HASH;

    return canonicalRequest;
}

/**
 * Splits the cached values into an array with two elements or returns an
 * empty array if the input string is invalid. The first element contains
 * the eight digit date string and the second element contains a JSON string
 * of the kSigningHash.
 *
 * @param cached input string to parse
 * @returns {string[]|*[]} array containing eight digit date and kSigningHash or empty
 * @private
 */
function splitCachedValues(cached) {
    const matchedPos = cached.indexOf(':', 0);
    // Do a sanity check on the position returned, if it isn't sane, return
    // an empty array and let the caller logic process it.
    if (matchedPos < 0 || matchedPos + 1 > cached.length) {
        return []
    }

    const eightDigitDate = cached.substring(0, matchedPos);
    const kSigningHash = cached.substring(matchedPos + 1);

    return [eightDigitDate, kSigningHash]
}

/**
 * Creates a signing key HMAC. This value is used to sign the request made to
 * the API.
 *
 * @param kSecret {string} secret access key
 * @param eightDigitDate {string} date in the form of 'YYYYMMDD'
 * @param service {string} name of service that request is for e.g. s3, iam, etc
 * @param region {string} region associated with server API
 * @returns {ArrayBuffer} signing HMAC
 * @private
 */
function buildSigningKeyHash(kSecret, eightDigitDate, service, region) {
    const kDate = mod_hmac.createHmac('sha256', 'AWS4'.concat(kSecret))
        .update(eightDigitDate).digest();
    const kRegion = mod_hmac.createHmac('sha256', kDate)
        .update(region).digest();
    const kService = mod_hmac.createHmac('sha256', kRegion)
        .update(service).digest();
    const kSigning = mod_hmac.createHmac('sha256', kService)
        .update('aws4_request').digest();

    return kSigning;
}

/**
 * Outputs the timestamp used to sign the request, so that it can be added to
 * the 'x-amz-date' header and sent by NGINX. The output format is
 * ISO 8601: YYYYMMDD'T'HHMMSS'Z'.
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html | Handling dates in Signature Version 4}
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {string} ISO 8601 timestamp
 */
function awsHeaderDate(r) {
    return signedDateTime(NOW, _eightDigitDate(NOW));
}

/**
 * Formats a timestamp into a date string in the format 'YYYYMMDD'.
 *
 * @param timestamp {Date} timestamp used in signature
 * @returns {string} a formatted date string based on the input timestamp
 * @private
 */
function _eightDigitDate(timestamp) {
    const year = timestamp.getUTCFullYear();
    const month = timestamp.getUTCMonth() + 1;
    const day = timestamp.getUTCDate();

    return ''.concat(_padWithLeadingZeros(year, 4),
        _padWithLeadingZeros(month,2),
        _padWithLeadingZeros(day,2));
}

/**
 * Creates a string in the ISO601 date format (YYYYMMDD'T'HHMMSS'Z') based on
 * the supplied timestamp and date. The date is not extracted from the timestamp
 * because that operation is already done once during the signing process.
 *
 * @param timestamp {Date} timestamp to extract date from
 * @param eightDigitDate {string} 'YYYYMMDD' format date string that was already extracted from timestamp
 * @returns {string} string in the format of YYYYMMDD'T'HHMMSS'Z'
 * @private
 */
function signedDateTime(timestamp, eightDigitDate) {
    const hours = timestamp.getUTCHours();
    const minutes = timestamp.getUTCMinutes();
    const seconds = timestamp.getUTCSeconds();

    return ''.concat(
        eightDigitDate,
        'T', _padWithLeadingZeros(hours, 2),
        _padWithLeadingZeros(minutes, 2),
        _padWithLeadingZeros(seconds, 2),
        'Z');
}

/**
 * Pads the supplied number with leading zeros.
 *
 * @param num {number|string} number to pad
 * @param size number of leading zeros to pad
 * @returns {string} a string with leading zeros
 * @private
 */
function _padWithLeadingZeros(num, size) {
    const s = "0" + num;
    return s.substr(s.length-size);
}

/**
 * Outputs the timestamp used to sign the request, so that it can be added to
 * the 'Date' header and sent by NGINX.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {string} RFC2616 timestamp
 */
function signedDate(r) {
    return NOW.toUTCString();
}

/**
 * Get the current session token from the instance profile credential cache.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {string} current session token or empty string
 */
function securityToken(r) {
    const credentials = readCredentials(r);
    if (credentials.sessionToken) {
        return credentials.sessionToken;
    }
    return '';
}

/**
 * Get the instance profile credentials needed to be authenticated against AWS
 * services like S3 and Lambda from a backend cache. If the credentials cannot
 * be found, then return undefined.
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string|null), expiration: (string|null)}} AWS instance profile credentials or undefined
 */
function readCredentials(r) {
    if (process.env['AWS_ACCESS_KEY_ID'] && process.env['AWS_SECRET_ACCESS_KEY']) {
        return {
            accessKeyId: process.env['AWS_ACCESS_KEY_ID'],
            secretAccessKey: process.env['AWS_SECRET_ACCESS_KEY'],
            sessionToken: null,
            expiration: null
        };
    }

    if ("variables" in r && r.variables.cache_instance_credentials_enabled == 1) {
        return _readCredentialsFromKeyValStore(r);
    } else {
        return _readCredentialsFromFile();
    }
}

/**
 * Read credentials from the NGINX Keyval store. If it is not found, then
 * return undefined.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials or undefined
 * @private
 */
function _readCredentialsFromKeyValStore(r) {
    const cached = r.variables.instance_credential_json;

    if (!cached) {
        return undefined;
    }

    try {
        return JSON.parse(cached);
    } catch (e) {
        debug_log(r, `Error parsing JSON value from r.variables.instance_credential_json: ${e}`);
        return undefined;
    }
}

/**
 * Returns the path to the credentials temporary cache file.
 *
 * @returns {string} path on the file system to credentials cache file
 * @private
 */
function _credentialsTempFile() {
    if (process.env['AWS_CREDENTIALS_TEMP_FILE']) {
        return process.env['AWS_CREDENTIALS_TEMP_FILE'];
    }
    if (process.env['TMPDIR']) {
        return `${process.env['TMPDIR']}/credentials.json`
    }

    return '/tmp/credentials.json';
}

/**
 * Read the contents of the credentials file into memory. If it is not
 * found, then return undefined.
 *
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials or undefined
 * @private
 */
function _readCredentialsFromFile() {
    const credsFilePath = _credentialsTempFile();

    try {
        const creds = fs.readFileSync(credsFilePath);
        return JSON.parse(creds);
    } catch (e) {
        /* Do not throw an exception in the case of when the
           credentials file path is invalid in order to signal to
           the caller that such a file has not been created yet. */
        if (e.code === 'ENOENT') {
            return undefined;
        }
        throw e;
    }
}

/**
 * Write the instance profile credentials to a caching backend.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 */
function writeCredentials(r, credentials) {
    /* Do not bother writing credentials if we are running in a mode where we
       do not need instance credentials. */
    if (process.env['AWS_ACCESS_KEY_ID'] && process.env['AWS_SECRET_ACCESS_KEY']) {
        return;
    }

    if (!credentials) {
        throw `Cannot write invalid credentials: ${JSON.stringify(credentials)}`;
    }

    if ("variables" in r && r.variables.cache_instance_credentials_enabled == 1) {
        _writeCredentialsToKeyValStore(r, credentials);
    } else {
        _writeCredentialsToFile(credentials);
    }
}

/**
 * Write the instance profile credentials to the NGINX Keyval store.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 * @private
 */
function _writeCredentialsToKeyValStore(r, credentials) {
    r.variables.instance_credential_json = JSON.stringify(credentials);
}

/**
 * Write the instance profile credentials to a file on the file system. This
 * file will be quite small and should end up in the file cache relatively
 * quickly if it is repeatedly read.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 * @private
 */
function _writeCredentialsToFile(credentials) {
    fs.writeFileSync(_credentialsTempFile(), JSON.stringify(credentials));
}

/**
 * Get the credentials needed to generate AWS signatures from the EC2
 * metadata endpoint.
 *
 * @returns {Promise<{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}>}
 * @private
 */
async function _fetchEC2RoleCredentials() {
    const tokenResp = await ngx.fetch(EC2_IMDS_TOKEN_ENDPOINT, {
        headers: {
            'x-aws-ec2-metadata-token-ttl-seconds': '21600',
        },
        method: 'PUT',
    });
    const token = await tokenResp.text();
    let resp = await ngx.fetch(EC2_IMDS_SECURITY_CREDENTIALS_ENDPOINT, {
        headers: {
            'x-aws-ec2-metadata-token': token,
        },
    });
    /* This _might_ get multiple possible roles in other scenarios, however,
       EC2 supports attaching one role only.It should therefore be safe to take
       the whole output, even given IMDS _might_ (?) be able to return multiple
       roles. */
    const credName = await resp.text();
    if (credName === "") {
        throw 'No credentials available for EC2 instance';
    }
    resp = await ngx.fetch(EC2_IMDS_SECURITY_CREDENTIALS_ENDPOINT + credName, {
        headers: {
            'x-aws-ec2-metadata-token': token,
        },
    });
    const creds = await resp.json();

    return {
        accessKeyId: creds.AccessKeyId,
        secretAccessKey: creds.SecretAccessKey,
        sessionToken: creds.Token,
        expiration: creds.Expiration,
    };
}

/**
 * Get the credentials by assuming calling AssumeRoleWithWebIdentity with the environment variable
 * values ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE and HOSTNAME
 *
 * @returns {Promise<{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}>}
 * @private
 */
async function _fetchWebIdentityCredentials() {
    const arn = process.env['AWS_ROLE_ARN'];
    const name = process.env['HOSTNAME'] || DEFAULT_ROLE_SESSION_NAME;

    let sts_endpoint = process.env['STS_ENDPOINT'];
    if (!sts_endpoint) {
        /* On EKS, the ServiceAccount can be annotated with
           'eks.amazonaws.com/sts-regional-endpoints' to control
           the usage of regional endpoints. We are using the same standard
           environment variable here as the AWS SDK. This is with the exception
           of replacing the value `legacy` with `global` to match what EKS sets
           the variable to.
           See: https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html
           See: https://docs.aws.amazon.com/eks/latest/userguide/configure-sts-endpoint.html */
        const sts_regional = process.env['AWS_STS_REGIONAL_ENDPOINTS'] || 'global';
        if (sts_regional === 'regional') {
            /* STS regional endpoints can be derived from the region's name.
               See: https://docs.aws.amazon.com/general/latest/gr/sts.html */
            const region = process.env['AWS_REGION'];
            if (region) {
                sts_endpoint = `https://sts.${region}.amazonaws.com`;
            } else {
                throw 'Missing required AWS_REGION env variable';
            }
        } else {
            // This is the default global endpoint
            sts_endpoint = 'https://sts.amazonaws.com';
        }
    }

    const token = fs.readFileSync(process.env['AWS_WEB_IDENTITY_TOKEN_FILE']);

    const params = `Version=2011-06-15&Action=AssumeRoleWithWebIdentity&RoleArn=${arn}&RoleSessionName=${name}&WebIdentityToken=${token}`;

    const response = await ngx.fetch(sts_endpoint + "?" + params, {
        headers: {
            "Accept": "application/json"
        },
        method: 'GET',
    });

    const resp = await response.json();
    const creds = resp.AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials;

    return {
        accessKeyId: creds.AccessKeyId,
        secretAccessKey: creds.SecretAccessKey,
        sessionToken: creds.SessionToken,
        expiration: creds.Expiration,
    };
}

/**
 * Creates a string to sign by concatenating together multiple parameters required
 * by the signatures algorithm.
 *
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html | String to Sign}
 * @param amzDatetime {string} ISO8601 timestamp string to sign request with
 * @param eightDigitDate {string} date in the form of 'YYYYMMDD'
 * @param region {string} region associated with server API
 * @param canonicalRequestHash {string} hex encoded hash of canonical request string
 * @param service {string} service code (for example, s3, lambda)
 * @returns {string} a concatenated string of the passed parameters formatted for signatures
 * @private
 */
function buildStringToSign(amzDatetime, eightDigitDate, region, service, canonicalRequestHash) {
    return 'AWS4-HMAC-SHA256\n' +
        amzDatetime + '\n' +
        eightDigitDate + '/' + region + '/' + service + '/aws4_request\n' +
        canonicalRequestHash;
}

/**
 * Outputs a log message to the request logger if debug messages are enabled.
 *
 * @param r {Request} HTTP request object
 * @param msg {string} message to log
 * @private
 */
function debug_log(r, msg) {
    if (DEBUG && "log" in r) {
        r.log(msg);
    }
}

/**
 * Parses a string to and returns a boolean value based on its value. If the
 * string can't be parsed, this method returns false.
 *
 * @param string {*} value representing a boolean
 * @returns {boolean} boolean value of string
 * @private
 */
function parseBoolean(string) {
    switch(string) {
        case "TRUE":
        case "true":
        case "True":
        case "YES":
        case "yes":
        case "Yes":
        case "1":
            return true;
        default:
            return false;
    }
}

/**
 * Offset to the expiration of credentials, when they should be considered expired and refreshed. The maximum
 * time here can be 5 minutes, the IMDS and ECS credentials endpoint will make sure that each returned set of credentials
 * is valid for at least another 5 minutes.
 *
 * To make sure we always refresh the credentials instead of retrieving the same again, keep credentials until 4:30 minutes
 * before they really expire.
 *
 * @type {number}
 */
const maxValidityOffsetMs = 4.5 * 60 * 1000;

/**
 * Get the credentials needed to create AWS signatures in order to authenticate
 * to S3. If the gateway is being provided credentials via a instance profile
 * credential as provided over the metadata endpoint, this function will:
 * 1. Try to read the credentials from cache
 * 2. Determine if the credentials are stale
 * 3. If the cached credentials are missing or stale, it gets new credentials
 *    from the metadata endpoint.
 * 4. If new credentials were pulled, it writes the credentials back to the
 *    cache.
 *
 * If the gateway is not using instance profile credentials, then this function
 * quickly exits.
 *
 * @param r {Request} HTTP request object
 * @returns {Promise<void>}
 */
async function fetchCredentials(r) {
    /* If we are not using an AWS instance profile to set our credentials we
       exit quickly and don't write a credentials file. */
    if (process.env['AWS_ACCESS_KEY_ID'] && process.env['AWS_SECRET_ACCESS_KEY']) {
        r.return(200);
        return;
    }

    let current;

    try {
        current = readCredentials(r);
    } catch (e) {
        debug_log(r, `Could not read credentials: ${e}`);
        r.return(500);
        return;
    }

    if (current) {
        // AWS returns Unix timestamps in seconds, but in Date constructor we should provide timestamp in milliseconds
        const exp = new Date(current.expiration * 1000).getTime() - maxValidityOffsetMs;
        if (NOW.getTime() < exp) {
            r.return(200);
            return;
        }
    }

    let credentials;

    debug_log(r, 'Cached credentials are expired or not present, requesting new ones');

    if (process.env['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']) {
        const uri = ECS_CREDENTIAL_BASE_URI + process.env['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'];
        try {
            credentials = await _fetchEcsRoleCredentials(uri);
        } catch (e) {
            debug_log(r, 'Could not load ECS task role credentials: ' + JSON.stringify(e));
            r.return(500);
            return;
        }
    }
    else if(process.env['AWS_WEB_IDENTITY_TOKEN_FILE']) {
        try {
            credentials = await _fetchWebIdentityCredentials()
        } catch(e) {
            debug_log(r, 'Could not assume role using web identity: ' + JSON.stringify(e));
            r.return(500);
            return;
        }
    } else {
        try {
            credentials = await _fetchEC2RoleCredentials();
        } catch (e) {
            debug_log(r, 'Could not load EC2 task role credentials: ' + JSON.stringify(e));
            r.return(500);
            return;
        }
    }
    try {
        writeCredentials(r, credentials);
    } catch (e) {
        debug_log(r, `Could not write credentials: ${e}`);
        r.return(500);
        return;
    }
    r.return(200);
}

/**
 * Get the credentials needed to generate AWS signatures from the ECS
 * (Elastic Container Service) metadata endpoint.
 *
 * @param credentialsUri {string} endpoint to get credentials from
 * @returns {Promise<{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}>}
 * @private
 */
async function _fetchEcsRoleCredentials(credentialsUri) {
    const resp = await ngx.fetch(credentialsUri);
    if (!resp.ok) {
        throw 'Credentials endpoint response was not ok.';
    }
    const creds = await resp.json();

    return {
        accessKeyId: creds.AccessKeyId,
        secretAccessKey: creds.SecretAccessKey,
        sessionToken: creds.Token,
        expiration: creds.Expiration,
    };
}

/**
 * Create HTTP Authorization header for authenticating with an AWS compatible
 * v4 API.
 *
 * @param r {Request} HTTP request object
 * @param timestamp {Date} timestamp associated with request (must fall within a skew)
 * @param region {string} API region associated with request
 * @param service {string} service code (for example, s3, lambda)
 * @param method {string} The HTTP method to create a canonical request
 * @param uri {string} The URI-encoded version of the absolute path component URL to create a canonical request
 * @param queryParams {string} The URL-encoded query string parameters to create a canonical request
 * @param host {string} HTTP host header value
 * @param credentials {object} Credential object with AWS credentials in it (AccessKeyId, SecretAccessKey, SessionToken)
 * @returns {string} HTTP Authorization header value
 */
function signatureV4(
    r, timestamp, region, service, method, uri, queryParams, host, credentials) {
    const eightDigitDate = _eightDigitDate(timestamp);
    const amzDatetime = signedDateTime(timestamp, eightDigitDate);
    const canonicalRequest = buildCanonicalRequest(
        method, uri, queryParams, host, amzDatetime, credentials.sessionToken);
    const signature = _buildSignatureV4(r, amzDatetime, eightDigitDate,
        credentials, region, service, canonicalRequest);
    const authHeader = 'AWS4-HMAC-SHA256 Credential='
        .concat(credentials.accessKeyId, '/', eightDigitDate, '/', region, '/',
            service, '/aws4_request,', 'SignedHeaders=',
            signedHeaders(credentials.sessionToken), ',Signature=', signature);

    debug_log(r, 'AWS v4 Auth header: [' + authHeader + ']');

    return authHeader;
}

/**
 * Creates a signature for use authenticating against an AWS compatible API.
 *
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html | AWS V4 Signing Process}
 * @param r {Request} HTTP request object
 * @param amzDatetime {string} ISO8601 timestamp string to sign request with
 * @param creds {object} AWS credentials
 * @param eightDigitDate {string} date in the form of 'YYYYMMDD'
 * @param region {string} API region associated with request
 * @param service {string} service code (for example, s3, lambda)
 * @param canonicalRequest {string} string with concatenated request parameters
 * @returns {string} hex encoded hash of signature HMAC value
 * @private
 */
function _buildSignatureV4(
    r, amzDatetime, eightDigitDate, creds, region, service, canonicalRequest) {
    debug_log(r, 'AWS v4 Auth Canonical Request: [' + canonicalRequest + ']');

    const canonicalRequestHash = mod_hmac.createHash('sha256')
        .update(canonicalRequest)
        .digest('hex');

    debug_log(r, 'AWS v4 Auth Canonical Request Hash: [' + canonicalRequestHash + ']');

    const stringToSign = buildStringToSign(
        amzDatetime, eightDigitDate, region, service, canonicalRequestHash);

    debug_log(r, 'AWS v4 Auth Signing String: [' + stringToSign + ']');

    let kSigningHash;

    /* If we have a keyval zone and key defined for caching the signing key hash,
     * then signing key caching will be enabled. By caching signing keys we can
     * accelerate the signing process because we will have four less HMAC
     * operations that have to be performed per incoming request. The signing
     * key expires every day, so our cache key can persist for 24 hours safely.
     */
    if ("variables" in r && r.variables.cache_signing_key_enabled == 1) {
        // cached value is in the format: [eightDigitDate]:[signingKeyHash]
        const cached = "signing_key_hash" in r.variables ? r.variables.signing_key_hash : "";
        const fields = splitCachedValues(cached);
        const cachedEightDigitDate = fields[0];
        const cacheIsValid = fields.length === 2 && eightDigitDate === cachedEightDigitDate;

        // If true, use cached value
        if (cacheIsValid) {
            debug_log(r, 'AWS v4 Using cached Signing Key Hash');
            /* We are forced to JSON encode the string returned from the HMAC
             * operation because it is in a very specific format that include
             * binary data and in order to preserve that data when persisting
             * we encode it as JSON. By doing so we can gracefully decode it
             * when reading from the cache. */
            kSigningHash = Buffer.from(JSON.parse(fields[1]));
        // Otherwise, generate a new signing key hash and store it in the cache
        } else {
            kSigningHash = buildSigningKeyHash(creds.secretAccessKey, eightDigitDate, service, region);
            debug_log(r, 'Writing key: ' + eightDigitDate + ':' + kSigningHash.toString('hex'));
            r.variables.signing_key_hash = eightDigitDate + ':' + JSON.stringify(kSigningHash);
        }
    // Otherwise, don't use caching at all (like when we are using NGINX OSS)
    } else {
        kSigningHash = buildSigningKeyHash(creds.secretAccessKey, eightDigitDate, service, region);
    }

    debug_log(r, 'AWS v4 Signing Key Hash: [' + kSigningHash.toString('hex') + ']');

    const signature = mod_hmac.createHmac('sha256', kSigningHash)
        .update(stringToSign).digest('hex');

    debug_log(r, 'AWS v4 Authorization Header: [' + signature + ']');

    return signature;
}

export default {
    awsHeaderDate,
    buildCanonicalRequest,
    buildSigningKeyHash,
    buildStringToSign,
    debug_log,
    fetchCredentials,
    parseBoolean,
    readCredentials,
    securityToken,
    signatureV4,
    signedHeaders,
    signedDate,
    signedDateTime,
    splitCachedValues,
    writeCredentials,
    // These functions do not need to be exposed, but they are exposed so that
    // unit tests can run against them.
    _credentialsTempFile,
    _eightDigitDate,
    _fetchEC2RoleCredentials,
    _fetchWebIdentityCredentials,
    _padWithLeadingZeros,
    _readCredentialsFromFile,
    _readCredentialsFromKeyValStore,
    _writeCredentialsToFile,
    _writeCredentialsToKeyValStore
}
