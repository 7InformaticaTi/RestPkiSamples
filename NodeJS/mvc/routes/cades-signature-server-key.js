var express = require('express');
var request = require('request');
var fs = require('fs');
var crypto = require('crypto');
var uuid = require('node-uuid');
var restPki = require('../lacuna-restpki'),
    CadesSignatureStarter = restPki.CadesSignatureStarter,
    CadesSignatureFinisher = restPki.CadesSignatureFinisher,
    StandardSignaturePolicies = restPki.StandardSignaturePolicies;
var client = require('../restpki-client');

var router = express.Router();
var appRoot = process.cwd();

/**
 * GET /cades-signature-server-key
 * 
 * This route performs a CAdES signature using REST PKI and PEM-encoded files for a certificate and for its private key. 
 * It renders the signature page.
 */
router.get('/', function(req, res, next) {

    var userfile = req.query.userfile;
    var cmsfile = req.query.cmsfile;

    // Instantiate the CadesSignatureStarter class, responsible for receiving the signature elements and start the
    // signature process
    var signatureStarter = new CadesSignatureStarter(client.getRestPkiClient());

    // Set PEM-encoded certificate file for ("Pierre de Fermat")
	signatureStarter.setSignerCertificateRaw(fs.readFileSync('./resources/fermat-cert.pem'));

    if (userfile) {

        // If the URL argument "userfile" is filled, it means the user was redirected here by the file upload.php
        // (signature with file uploaded by user). We'll set the path of the file to be signed, which was saved in the
        // "public/app-data" folder by the route "upload".
        signatureStarter.setFileToSignFromPath('/public/app-data/' + userfile);
    } else if (cmsfile) {

        /*
         * If the URL argument "cmsfile" is filled, the user has asked to co-sign a previously signed CMS. We'll set the
         * path to the CMS to be co-signed, which was previously saved in the "public/app-data":
         *
         * 1. The CMS to be co-signed must be set using the method "setCmsToCoSign" or "setCmsFileToCoSign", not the
         *    method "setContentToSign" nor "setFileToSign".
         *
         * 2. Since we're creating CMSs with encapsulated content (see call to setEncapsulateContent below), we don't
         *    need to set the content to be signed, REST PKI will get the content from the CMS being co-signed.
         */
        signatureStarter.setCmsToCoSignFromPath('/public/app-data/' + cmsfile);
    } else {

        // If both userfile and cmsfile are null, this is the "signature with server file" case. We'll set the path to
        // the sample document.
        signatureStarter.setFileToSignFromPath('/public/SampleDocument.pdf');
    }

    // Set the signature policy
    signatureStarter.setSignaturePolicy(StandardSignaturePolicies.pkiBrazilCadesAdrBasica);

    // For this sample, we'll use the Lacuna Test PKI as our security context in order to accept our test certificate
    // used above ("Pierre de Fermat"). This security context should be used ***** FOR DEVELOPMENT PUPOSES ONLY *****
    signatureStarter.setSecurityContext('803517ad-3bbc-4169-b085-60053a8f6dbf');

    // Optionally, set whether the content should be encapsulated in the resulting CMS. If this parameter is ommitted,
    // the following rules apply:
    // - If no CmsToCoSign is given, the resulting CMS will include the content
    // - If a CmsToCoSign is given, the resulting CMS will include the content if and only if the CmsToCoSign also
    // includes the content
    signatureStarter.setEncapsulateContent(true);

    // Call the start() method, which initiates the signature. This yields the parameters for the signature using the
    // certificate
    signatureStarter.startAsync().then(function(signatureParams) {

        // Read PEM-encoded private-key file for ("Pierre de Fermat")
        var pkey = fs.readFileSync('./resources/fermat-pkey.pem', 'binary');

        // Create a new signature, setting the algorithm that will be used
        var sign = crypto.createSign(signatureParams.signatureAlgorithm);

        // Set the data that will be signed
        sign.write(signatureParams.toSignData);
        sign.end();

        // Perform the signature and receives the signature content
        var signature = sign.sign({ key: pkey, passphrase: '1234' });

        // Instantiate the CadesSignatureFinisher class, responsible for completing the signature process
        var signatureFinisher = new CadesSignatureFinisher(client.getRestPkiClient());

        // Set the token
        signatureFinisher.setToken(signatureParams.token);

        // Set the signature
        signatureFinisher.setSignatureRaw(signature);

        // Call the finishAsync() method, which finalizes the signature process
        signatureFinisher.finishAsync().then(function(cms) {

            // Get information about the certificate used by the user to sign the file. This method must only be called
            // after calling the finishAsync() method.
            var signerCert = signatureFinisher.getCertificateInfo();

            // At this point, you'd typically swtore the CMS on your database. For demonstration purposes, we'll store
            // the CMS on a temporary folder publicly accessible and render a link to it.
            var filename = uuid.v4() + '.p7s';
            var appDataPath = appRoot + '/public/app-data/';
            if (!fs.existsSync(appDataPath)) {
                fs.mkdirSync(appDataPath);
            }
            fs.writeFileSync(appDataPath + filename, cms);

            // Render the signature completed page
            res.render('cades-signature-complete', {
                signedFileName: filename,
                signerCert: signerCert
            });

        }).catch(function(error) {
            next(error);
        });

    }).catch(function(error) {
        next(error);
    });
});

module.exports = router;