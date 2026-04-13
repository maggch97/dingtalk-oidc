// Example JavaScript function to transform OIDC claims.
// This function will be executed before signing the ID token.
// The second argument contains request context such as redirect_uri.

function transform(claims, context) {
    // Example 1: Add custom groups/roles based on user email
    if (claims.email) {
        if (claims.email.endsWith('@admin.example.com')) {
            claims.groups = ['admin', 'users'];
            claims.role = 'admin';
        } else if (claims.email.endsWith('@example.com')) {
            claims.groups = ['users'];
            claims.role = 'user';
        } else {
            claims.groups = ['guest'];
            claims.role = 'guest';
        }
    }

    // Example 2: Add organization information
    claims.organization = 'MyCompany';

    // Example 3: Include the original OIDC redirect_uri in the token if needed
    if (context && context.redirect_uri) {
        claims.redirect_uri = context.redirect_uri;
    }

    // Example 4: Add preferred username from email
    if (claims.email) {
        claims.preferred_username = claims.email.split('@')[0];
    }

    // IMPORTANT: Always return the claims object
    return claims;
}
