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

import aws from "./aws_common.js"

/**
 * The current moment as a timestamp. This timestamp will be used across
 * functions in order for there to be no variations in signatures.
 * @type {Date}
 */
const NOW = new Date();

/**
 * Constant defining the service requests are being signed for.
 * @type {string}
 */
const SERVICE = 'lambda';

/**
 * Creates an AWS authentication signature based on the global settings and
 * the passed request parameter.
 *
 * @param r {Request} HTTP request object
 * @returns {string} AWS authentication signature
 */
function lambdaAuth(r) {
    const host = process.env['LAMBDA_SERVER'];
    const region = process.env['LAMBDA_REGION'];
    const queryParams = '';
    const uri = '/2015-03-31/' + r.request_uri + '/invocations';
    r.log("##### Lambda Auth: URI: " + uri);
    const credentials = aws.readCredentials(r);
    let signature = aws.signatureV4(r, NOW, region, SERVICE,
        r.method, uri, queryParams, host, credentials);
    return signature;
}

export default {
    lambdaAuth,
};
