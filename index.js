const jose = require('node-jose')

module.exports = async (token, tokenType = 'id', JWKS, ClientId) => {
    const sections = token.split('.')
    const header = JSON.parse(jose.util.base64url.decode(sections[0]))
    const kid = header.kid

    const key = JWKS.keys.find(obj => obj.kid === kid)

    if (!key) throw 'Public key not found in jwks.json'


    let result = await jose.JWK.asKey(key)
    try {
        result = await jose.JWS.createVerify(result).verify(token)
    } catch (e) {
        throw 'Signature verification failed'
    }

    const claims = JSON.parse(result.payload)
    const current_ts = Math.floor(new Date() / 1000)

    if (current_ts > claims.exp) throw 'Token is expired'

    if (claims.token_us === 'access'
        && tokenType === 'access'
        && claims.client_id !== ClientId
    ) throw 'Token was not issued for this client_id'
    else if (claims.aud !== ClientId) throw 'Token was not issued for this audience'

    return claims
}
