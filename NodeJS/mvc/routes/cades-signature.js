var express = require('express');
var request = require('request');
var fs = require('fs');
var uuid = require('node-uuid');
var restPki = require('../lacuna-restpki'),
    CadesSignatureStarter = restPki.CadesSignatureStarter,
    CadesSignatureFinisher = restPki.CadesSignatureFinisher,
    StandardSignaturePolicies = restPki.StandardSignaturePolicies,
    StandardSecurityContexts = restPki.StandardSecurityContexts;
var client = require('../restpki-client');

var router = express.Router();
var appRoot = process.cwd();


/*
 * GET /cades-signature
 *
 * This route initiates a CAdES signature using REST PKI and renders the signature page.
 *
 * All CAdES signature examples converge to this action, but with different URL arguments:
 *
 * 1. Signature with a server file               : no arguments filled
 * 2. Signature with a file uploaded by the user : "userfile" filled
 * 3. Co-signature of a previously signed CMS    : "cmsfile" filled
 */
router.get('/', function (req, res, next) {

    var userfile = req.query.userfile;
    var cmsfile = req.query.cmsfile;

    // Instantiate the CadesSignatureStarter class, responsible for receiving the signature elements and start the
    // signature process
    var signatureStarter = new CadesSignatureStarter(client.getRestPkiClient());

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

    // Optionally, set a SecurityContext to be used to determine trust in the certificate chain
    // signatureStarter.setSecurityContext(StandardSecurityContexts.pkiBrazil);
    // Note: Depending on the signature policy chosen above, setting the security context may be mandatory (this is not
    // the case for ICP-Brasil policies, which will automatically use the PKI_BRAZIL security context if none is passed)

    // Optionally, set whether the content should be encapsulated in the resulting CMS. If this parameter is omitted,
    // the following rules apply:
    // - If no CmsToCoSign is given, the resulting CMS will include the content
    // - If a CmsToCoSign is given, the resulting CMS will include the content if and only if the CmsToCoSign also
    //   includes the content
    signatureStarter.setEncapsulateContent(true);

    // Call the startWithWebPki() method, which initiates the signature. This yields the token, a 43-character
    // case-sensitive URL-safe string, which identifies this signature process. We'll use this value to call the
    // signWithRestPki() method on the Web PKI component (see javascript below) and also to complete the signature after
    // the form is submitted (see file pades-signature-action.php). This should not be mistaken with the API access
    // token.
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
        res.render('cades-signature', {
            token: token,
            userfile: userfile,
            cmsfile: cmsfile
        });

    }).catch(function(error) {
        next(error);
    });
});

/*
 * POST /cades-signature
 *
 * This route receives the form submission from the view 'cades-signature'. We'll call REST PKI to complete the
 * signature.
 */
router.post('/', function (req, res, next) {

    // Retrieve the token from the URL
    var token = req.body.token;

    // Instantiate the CadesSignatureFinisher class, responsible for completing the signature process
    var signatureFinisher = new CadesSignatureFinisher(client.getRestPkiClient());

    // Set the token
    signatureFinisher.setToken(token);

    // Call the finishAsync() method, which finalizes the signature process and returns the CMS (p7s file) bytes
    signatureFinisher.finishAsync().then(function(cms) {

        // Get information about the certificate used by the user to sign the file. This method must only be called
        // after calling the finishAsync() method.
        var signerCert = signatureFinisher.getCertificateInfo();

        // At this point, you'd typically swtore the CMS on your database. For demonstration purposes, we'll store the
        // CMS on a temporary folder publicly accessible and render a link to it.
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
});

module.exports = router;
