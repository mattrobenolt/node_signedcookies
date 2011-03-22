var crypto = require('crypto'),
    pattern = new RegExp(/^(?:([0-9a-f]+):)?(.*)$/);

module.exports = function signedCookies(secret, digest) {
    digest = digest || 'sha1';
    
    function unsign(key, signed_value)
    {
        var matches = signed_cookie_pattern.exec(signed_value);
        
        if(matches && matches.length === 3)
        {
            var signature = matches[1],
                unsigned_value = matches[2];
                
            if(signature === get_digest(key, unsigned_value))
            {
                return unsigned_value;
            }
        }

        return false;
    }
    
    function get_digest(key, value)
    {
        var hmac = crypto.createHmac(digest, secret);
        hmac.update(key+':'+value);
        
        return hmac.digest('hex');
    };
    
    return function(req, res, next) {
        for(var morsel in req.cookies)
        {
            var decoded = unsign(morsel, req.cookies[morsel]);
            if(false === decoded){
                // cookie is not signed properly or has been tampered with
                delete req.cookies[morsel];
            }
            else
            {
                req.cookies[morsel] = decoded;
            }
        }
        next();
    }
};