/**
 * @file Template for an Auth0 Action to handle a Custom Token Exchange.
 * This script implements the common scenario of validating a third-party (Skyfire) JWT,
 * received as a subject_token, and exchanging it for an Auth0 access token.
 *
 * DISCLAIMER:
 * Custom Token Exchange gives you the added flexibility to set the user for the transaction
 * by taking on the additional responsibility of securely validating the corresponding
 * subject_token that identifies the user for the transaction.
 *
 * Remember that subject_tokens used with Custom Token Exchange can be any token format or
 * type you require, as long as your Action code can interpret them. You are responsible
 * for implementing strong validation of the tokens you receive and accept. Failing to do so
 * would make you liable for opening yourself up to different attack vectors, such as
 * spoofing or replay attacks, resulting in bad actors being able to authenticate with someone
 * else’s user ID.  https://auth0.com/docs/authenticate/custom-token-exchange#code-samples provides
 * best practices and examples for common scenarios for validating incoming subject tokens
 * in a secure and performant way.
 *
 * IMPORTANT: You must review and adapt this template to fit your specific configuration,
 * security, and application requirements. Access to modify this Action code must be strictly
 * controlled and limited to authorized personnel.
 */

const { jwtVerify, importJWK } = require('jose');
const { ManagementClient } = require("auth0");

var validator = require('validator');

// --- CONFIGURATION: REVIEW AND UPDATE ---
// The name of the Auth0 Database Connection where user profiles will be created or managed.
const DB_NAME = '{{DATABASE_CONNECTION}}';

// A list of API identifiers (audiences) that are allowed.
// To disable this check and allow any API, set this to: null
// To restrict to specific audiences, provide the list of identifiers, e.g., ['https://api.yourapp.com/']
// To allow no audiences, leave as an empty array: [] (SECURE BY DEFAULT)
// NOTE: Alternatively, you can manage API access via Auth0 Application settings.
// See: https://auth0.com/docs/get-started/apis/api-access-policies-for-applications
const ALLOWED_AUDIENCES = ['{{CUSTOM_API_IDENTIFIER}}']; 

// A list of allowed scopes.
// To disable this check and allow any scope, set this to: null
// To restrict to specific scopes, provide the list of values, e.g., ['read:data', 'write:data']
// To allow no scopes, leave as an empty array: [] (SECURE BY DEFAULT)
// NOTE: Alternatively, you can manage scope access via Auth0 Application settings.
// See: https://auth0.com/docs/get-started/apis/api-access-policies-for-applications
const ALLOWED_SCOPES = [];

// --- SKYFIRE TOKEN VERIFICATION DETAILS ---
// The JWKS endpoint URL for retrieving public keys to verify Skyfire token signatures.
const SKYFIRE_JWKS_URL = 'https://app.skyfire.xyz/.well-known/jwks.json';

// The expected 'iss' (issuer) claim for all Skyfire JWTs.
const SKYFIRE_JWT_ISSUER = 'https://app.skyfire.xyz';

// Network timeout for fetching keys.
const fetchTimeout = 5000;

/**
 * Handles the Custom Token Exchange request.
 * @param {Event} event - Details about the incoming token exchange request.
 * @param {CustomTokenExchangeAPI} api - Methods and utilities to define the token exchange process.
 */
exports.onExecuteCustomTokenExchange = async (event, api) => {
    // 2. Validate the target API (audience), if an allow-list is configured.
    if (ALLOWED_AUDIENCES !== null) {
        const requestedAudience = event.resource_server
            ? event.resource_server.identifier
            : null;
        if (
            !requestedAudience ||
            !ALLOWED_AUDIENCES.includes(requestedAudience)
        ) {
            return api.access.deny(
                'invalid_target',
                'The requested API (audience) is not allowed for this exchange.'
            );
        }
    }

    // 3. Validate that all requested scopes are allowed, if an allow-list is configured.
    if (ALLOWED_SCOPES !== null) {
        const requestedScopes = event.transaction.requested_scopes || [];
        if (!requestedScopes.every((scope) => ALLOWED_SCOPES.includes(scope))) {
            return api.access.deny(
                'invalid_scope',
                'One or more of the requested scopes are not allowed for this exchange.'
            );
        }
    }

    // 4. Validate the Skyfire subject token.
    const { isValid, payload, error } = await validateToken(
        event.transaction.subject_token
    );

    if (!isValid) {
        // If the token is invalid, deny access and terminate the flow.
        return api.access.deny('invalid_subject_token', error.message);
    }

    // 5. Check if user already exists in Auth0 using Management API v2
    const existingUser = await getUserByEmail(payload.bid.skyfireEmail);

    if (existingUser) {
        // User exists, use their existing user_id
        userId = existingUser.user_id;
        console.log(`Found existing user with ID: ${userId} for email: ${payload.bid.skyfireEmail}`);
        api.authentication.setUserById(existingUser.user_id);
        return;
    }

    const name = `${payload.bid.nameFirst} ${payload.bid.nameLast}`;
    const patch = {
        user_id: payload.sub,
        email: payload.bid.skyfireEmail,
        username: payload.sub,
        email_verified: true,
        verify_email: false,
    };
    // console.log("Patching with", patch);
    if (name) {
        patch.name = name;
    }

    if (payload.bid.nameFirst) {
        patch.given_name = payload.bid.nameFirst;
        patch.nickname  = payload.bid.nameFirst;
    }

    if (payload.bid.nameLast) {
        patch.family_name = payload.bid.nameLast;
    }


    // If the token is valid, provision the user in Auth0.
    api.authentication.setUserByConnection(
        DB_NAME,
        {
            ...patch
        },
        {
            creationBehavior: 'create_if_not_exists',
            updateBehavior: 'replace',
        }
    );

    /**
     * Gets a user by email using Auth0 Management API v2.
     * @param {string} email - The email address to search for.
     * @returns {Promise<object|null>} The user object if found, null otherwise.
     */
    async function getUserByEmail(email) {
        try {
            const management = new ManagementClient({
                domain: event.secrets.DOMAIN,
                clientId: event.secrets.CLIENT_ID,
                clientSecret: event.secrets.CLIENT_SECRET,
                scope: 'read:users'
            });

            const users = await management.users.listUsersByEmail({
                email
            });

            console.log("Found users", users);
            if (users && users.length > 0) {
                // Return the first user found with this email
                // In most cases, there should only be one user per email
                return users[0];
            }
            
            return null;
        } catch (err) {
            console.log(`Error fetching user by email ${email}:`, err.message);
            // If we can't fetch the user, we'll assume they don't exist
            // This allows the flow to continue and create a new user
            return null;
        }
    }

    /**
     * Validates the provided JWT. It verifies the signature against the JWKS,
     * checks standard claims via the 'jose' library, and performs additional
     * custom validations on the payload and header.
     * @param {string} subjectToken The JWT to validate.
     * @returns {Promise<{isValid: boolean, payload?: object, error?: {reason: string, message: string}}>}
     */
    async function validateToken(subjectToken) {
        try {
            /**
             * Asynchronously retrieves the public key for JWT verification.
             * It first checks the cache, falling back to fetching from the JWKS endpoint.
             * The algorithm is dynamically inferred from the 'alg' property of the fetched JWK.
             * @param {object} protectedHeader The protected header of the JWT.
             * @returns {Promise<import('jose').KeyLike>} A cryptographic key for verification.
             */
            const getKey = async (protectedHeader) => {
                const kid = protectedHeader.kid;
                if (!kid) {
                    throw new Error("JWT missing 'kid' in protected header.");
                }

                const cachedKey = api.cache.get(kid);
                let jwk;
                if (cachedKey) {
                    console.log(`Key ${kid} found in cache.`);
                    jwk = JSON.parse(cachedKey.value);
                } else {
                    console.log(
                        `Key ${kid} not found in cache, fetching from JWKS.`
                    );
                    jwk = await fetchKeyFromJWKS(kid);
                    if (jwk) {
                        // Cache the key for 10 minutes to reduce network requests.
                        api.cache.set(kid, JSON.stringify(jwk), {
                            ttl: 600000,
                        });
                    }
                }

                if (!jwk) {
                    throw new Error(
                        `Unable to find a signing key that matches '${kid}'.`
                    );
                }

                if (!jwk.alg) {
                    throw new Error(
                        "JWK is missing the 'alg' property required for verification."
                    );
                }

                // Import the JWK. 'jose' will automatically use the 'alg' property from the JWK for validation.
                return importJWK(jwk);
            };

            const { payload, protectedHeader } = await jwtVerify(
                subjectToken,
                getKey,
                {
                    issuer: SKYFIRE_JWT_ISSUER,
                }
            );

            // -- Additional Custom Validations --

            // 1. Validate 'typ' header: must be one of the expected types.
            if (!['kya+JWT', 'kya+pay+JWT'].includes(protectedHeader.typ)) {
                const message = 'typ should be one of kya+JWT or kya+pay+JWT.';
                console.log(
                    `Validation failed: ${message} (got: ${protectedHeader.typ})`
                );
                return {
                    isValid: false,
                    error: { reason: 'invalid_typ', message },
                };
            }

            // 2. Validate skyfireEmail format.
            if (
                !payload.bid ||
                !validator.isEmail(String(payload.bid.skyfireEmail))
            ) {
                const message =
                    "Invalid email format in 'bid.skyfireEmail' claim.";
                console.log(`Validation failed: ${message}`);
                return {
                    isValid: false,
                    error: { reason: 'invalid_email', message },
                };
            }

            // 3. Validate 'env' is 'production'.
            if (payload.env !== 'production') {
                const message = 'Token is not from production environment.';
                console.log(
                    `Validation failed: ${message} (got env: ${payload.env})`
                );
                return {
                    isValid: false,
                    error: { reason: 'invalid_env', message },
                };
            }

            // 4. Validate 'jti' (JWT ID) is a UUID.
            if (!payload.jti || !validator.isUUID(String(payload.jti))) {
                const message = 'Invalid token ID (jti): not a valid UUID.';
                console.log(`Validation failed: ${message}`);
                return {
                    isValid: false,
                    error: { reason: 'invalid_jti', message },
                };
            }

            // 5. Validate 'sub' (Subject) is a UUID.
            if (!payload.sub || !validator.isUUID(String(payload.sub))) {
                const message = 'Invalid subject (sub): not a valid UUID.';
                console.log(`Validation failed: ${message}`);
                return {
                    isValid: false,
                    error: { reason: 'invalid_sub', message },
                };
            }

            // 6. Validate 'aud' (Audience) is a UUID.
            if (!payload.aud || !validator.isUUID(String(payload.aud))) {
                const message = 'Invalid audience (aud): not a valid UUID.';
                console.log(`Validation failed: ${message}`);
                return {
                    isValid: false,
                    error: { reason: 'invalid_aud', message },
                };
            }

            // If all validations pass, the token is considered valid.
            return { isValid: true, payload };
        } catch (err) {
            // Improved logging to provide more detail on the error object.
            const errorDetails =
                err instanceof Error
                    ? err.message
                    : JSON.stringify(err, null, 2);
            console.log('JWT verification failed:', errorDetails);

            // Map 'jose' library errors to standardized error responses.
            let reason = 'invalid_token';
            let message = 'JWT verification failed: invalid token.';

            if (err.code === 'ERR_JWT_EXPIRED') {
                reason = 'token_expired';
                message = 'Token has expired.';
            } else if (err.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
                reason = 'invalid_claim';
                message = `Token claim validation failed: '${err.claim}' is invalid.`;
            } else if (err.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
                reason = 'invalid_signature';
                message = 'Token signature verification failed.';
            }

            return { isValid: false, error: { reason, message } };
        }
    }

    /**
     * Fetches a specific public signing key from the JWKS endpoint.
     * @param {string} kid - The Key ID of the key to fetch.
     * @returns {Promise<object|null>} The JWK object or null if not found.
     */
    async function fetchKeyFromJWKS(kid) {
        try {
            const controller = new AbortController();
            setTimeout(() => controller.abort(), fetchTimeout);

            const response = await fetch(SKYFIRE_JWKS_URL, {
                signal: controller.signal,
            });

            if (!response.ok) {
                console.log(
                    `Error fetching JWKS. Response status: ${response.status}`
                );
                throw new Error('Error fetching JWKS');
            }
            const jwks = await response.json();
            const key = jwks.keys.find((key) => key.kid === kid);
            if (!key) {
                console.log(`Key with kid '${kid}' not found in the JWKS.`);
                return null;
            }
            return key;
        } catch (err) {
            console.log(`Failed to fetch JWKS from URL: ${err.message}`);
            throw new Error(
                'Internal error fetching keys. Please try again later.'
            );
        }
    }
};