var express = require('express');
var request = require('request');
var fs = require('fs');
var uuid = require('node-uuid');
var restPki = require('../lacuna-restpki'),
    XmlElementSignatureStarter = restPki.XmlElementSignatureStarter,
    XmlSignatureFinisher = restPki.XmlSignatureFinisher,
    StandardSignaturePolicies = restPki.StandardSignaturePolicies,
    StandardSecurityContexts = restPki.StandardSecurityContexts;
var client = require('../restpki-client');

var router = express.Router();
var appRoot = process.cwd();


/*
 * GET /xml-element-signature
 *
 * This route initiates a XML element signature using REST PKI and renders the signature page.
 */
router.get('/', function (req, res, next) {

    // Instantiate the XmlElementSignatureStarter class, responsible for receiving the signature elements and start the
    // signature process
    var signatureStarter = new XmlElementSignatureStarter(client.getRestPkiClient());

    // Set the XML to be signed, a sample Brazilian fiscal invoice pre-generated
    signatureStarter.setXmlFileToSign('/public/SampleNFe.xml');

    // Set the ID of the element to be signed
    signatureStarter.setToSignElementId('NFe35141214314050000662550010001084271182362300');

    // Set the signature policy
    signatureStarter.setSignaturePolicyId(StandardSignaturePolicies.pkiBrazilNFePadraoNacional);

    // Optionally, set a SecurityContext to be used to determine trust in the certificate chain. Since we're using the
    // pkiBrazilNFePadraoNacional policy, the security context will default to PKI Brazil (ICP-Brasil)
    //signatureStarter.setSecurityContextId(StandardSecurityContexts.pkiBrazil);
    // Note: By changing the SecurityContext above you can accept only certificates from a custom PKI for tests.

    // Call the startWithWebPkiAsync() method, which initiates the signature. This yields the token, a 43-character
    // case-sensitive URL-safe string, which identifies this signature process. We'll use this value to call the
    // signWithRestPki() method on the Web PKI component (see javascript below) and also to complete the signature after
    // the form is submitted (see file xml-element-signature-action.php). This should not be mistaken with the API
    // access token.
    signatureStarter.startWithWebPkiAsync().then(function(token) {

        // The token acquired can only be used for a single signature attempt. In order to retry the signature it is
        // necessary to get a new token. This can be a problem if the user uses the back button of the browser, since
        // the browser might show a cached page that we rendered previously, with a now stale token. To prevent this
        // from happening, we set some response headers specifying that the page should not be cached.
        res.set({
            'Cache-Control': 'private, no-store, max-age=0, no-cache, must-revalidate, post-check=0, pre-check=0',
            'Pragma': 'no-cache'
        });

        // Render the signature page
        res.render('xml-element-signature', {
            token: token,
            userfile: req.query.userfile
        });

    }).catch(function(err, data) {
        next(err);
        console.warn(data);
    });
});

/*
 * POST /xml-element-signature
 *
 * This route receives the form submission from the view 'xml-full-signature'. We'll call REST PKI to complete the
 * signature.
 */
router.post('/', function (req, res, next) {

    // Retrieve the token from the URL
    var token = req.body.token;

    // Instantiate the XmlSignatureFinisher class, responsible for completing the signature process
    var signatureFinisher = new XmlSignatureFinisher(client.getRestPkiClient());

    // Set the token
    signatureFinisher.setToken(token);

    // Call the finishAsync() method, which finalizes the signature process and returns the signed XML
    signatureFinisher.finishAsync().then(function(signedXml) {

        // Get information about the certificate used by the user to sign the file. This method must only be called after
        // calling the finish() method.
        var signerCert = signatureFinisher.getCertificate();

        // At this point, you'd typically store the signed PDF on your database. For demonstration purposes, we'll
        // store the PDF on a temporary folder publicly accessible and render a link to it.
        var filename = uuid.v4() + '.xml';
        var appDataPath = appRoot + '/public/app-data/';
        if (!fs.existsSync(appDataPath)) {
            fs.mkdirSync(appDataPath);
        }
        fs.writeFileSync(appDataPath + filename, signedXml);

        // Render the signature completed page
        res.render('xml-signature-complete', {
            signedFileName: filename,
            signerCert: signerCert
        });

    }).catch(function(err, data) {
        next(err);
        console.warn(data.message);
    });
});

module.exports = router;
