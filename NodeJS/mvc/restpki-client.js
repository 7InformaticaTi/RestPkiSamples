var restPki = require('./lacuna-restpki'),
    RestPkiClient = restPki.RestPkiClient;

function getRestPkiClient() {
    // ------------------------------------------------------------------------------------------------
    // PLACE YOUR API ACCESS TOKEN BELOW
    var accessToken = 'PASTE YOUR API ACCESS TOKEN HERE';
    //                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    // ------------------------------------------------------------------------------------------------

    var restPkiUrl = 'https://pki.rest/';

    // Throw exception if token is not set (this check is here just for the sake of newcomers, you can remove it)
    if (!accessToken || accessToken.indexOf(' API ') >= 0) {
        throw new Error('The API access token was not set! Hint: to run this sample you must generate an API access token on the REST PKI website and paste it on the file routes/restpki-client.js');
    }

    return new RestPkiClient(restPkiUrl, accessToken);
}

module.exports = {
    getRestPkiClient: getRestPkiClient
};