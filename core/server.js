const settings = require('../settings');
const express  = require('express');
const bodyParser = require("body-parser");
//require('body-parser-xml')(bodyParser);
const helmet = require("helmet");
const compression = require("compression");
const app = express();

app.use(bodyParser.text({ type: '*/*' }));
app.use(helmet());  // reduces hacking
app.use(compression()); // compresses and makes faster
app.use(express.json()); 

//CORS Middleware
app.use(function (req, res, next) {
        //Enabling CORS 
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType,Content-Type, Accept, Authorization");
        next();
});

// set up for file services
const fs = require('fs');

// create either https server or http server... depending on confignode flag
// NOTE: It is typically better to set up this node.js process as http but 
// use a layer 7 load balancer like haproxy and use *.PEM cert files so your load balancer only deals with certs
// This way you update certs in 1 or 2 places rather than all members of a web farm, but your choice
if(settings.lHttps) {
    console.log("Setting up for HTTPS server");

    const https = require('https');

    // NOTE: all cert files have been removed... below is simply an example of how to set up https

    https.createServer({
        key: fs.readFileSync('xyz.key'),
        cert: fs.readFileSync('xyz.crt'),
        ca: [fs.readFileSync('gd1.crt'), fs.readFileSync('gd2.crt'), fs.readFileSync('gd3.crt')]
        }, app).listen(settings.webPort, function() {
            console.log("Started on PORT " + settings.webPort);
    });

} else {  // else set up http
    console.log("Setting up for HTTP server");
    const http = require('http');

    http.createServer({}, app).listen(settings.webPort, function() {
        console.log("node TC Response Receiver running on port: ", settings.webPort);
    });
 };    

//  The following 3 lines of code are not needed BUT...
// This code allows haproxy or most layer 7 loadbalancers to ping this site to see if it is up
// If it is not, the load balancer can detect no response and flag this server as down
// when this path "/siteup" is hit, these lines will simply return a status = 200 to satisfy a check site hit from a monitor
app.get("/siteup", function (req, res) {
    //console.log('site nodeTCResponseReceiverSample is up!'); optionally uncomment to see in the console
    res.end();
});

// using express, set up for POST with whatever path desired
app.post("/api/responsejson", function (req, res) {
    const name = req.query
    settings.gkClientUserID = null; // used to identify the incoming payload, "response" or whatever it may be

    // In the incoming query string check for a paramater called 'kClientUserID' and check that a valid GUID follows
    // If the GUID is defined in the query string but does not match client GUID.. force GUID to null so will report invalid GUID
    // You can ignore this hit if you wish, but it might lesson the damage from a denial service attack.
    // Note: You will have one GUID, i.e., 'kClientUserID', to reflect your account with TrueCordis
    // At some point, you should have received this from us.
    if(name.hasOwnProperty('kClientUserID') ) {
        settings.gkClientUserID = name.kClientUserID; //extract the querystring param and assign to a var in settings

        // Compare with your own valid guid
        if(settings.gkClientUserID  !== "24F06D3A-C510-4719-AD2A-3DDADFE43FBD") {  // does this match the user json4289test for clientid=3747?
            // If not, set to null
            settings.gkClientUserID = null;
        }
    };

    // if guid is null, then this may indicate a possible denial of service attack
    if(settings.gkClientUserID == null) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.write('');
        res.end();
        console.log('INVALID GUID! possible denial of service ATTACK!');
        // Here we will do a quick return to avoid hitting sql.
        // This will minimize damage if this really is a denial of service attack.
        return
    } 

    // If you get here, the hit should be valid
    console.log('VALID GUID!!! name = ',settings.gkClientUserID)

    let giRequestID = 'unknown';
    let gcControlNumber = 'unknown';
    // Next extract the body info and assume it is json
    let gjBody = JSON.parse(req.body);
    let iCode = 0;

    if('tcinterface' in gjBody) {
        if('confirm' in gjBody.tcinterface) {
            if('iRequestID' in gjBody.tcinterface.confirm) {
                giRequestID = gjBody.tcinterface.confirm.iRequestID;
            }
            if('cControlNumber' in gjBody.tcinterface.confirm) {
                gcControlNumber = gjBody.tcinterface.confirm.cControlNumber;
            }
        }
    } else {
        //console.log('body  = ',req.body)
        console.log('tcinterface is missing good "confirm" object.  TCinterface = ',gjBody.tcinterface);
    }

    console.log('gjBody = ',gjBody);
    // begin to parse parts of gjBody and display
    console.log('tcinterface  = ',gjBody.tcinterface);
    console.log('confirm  = ',gjBody.tcinterface.confirm);
    console.log('iRequestID  = ',gjBody.tcinterface.confirm.iRequestID);

    // Note: the following lines upto END BACKEND would probably be better on the backend.  Then return a 
    // START BACKEND

    // here is what the client should have stored in a table or container or in some config file:
    // This should never be stored in this app (unless hidden in a "secret" or environment var)
    const cVendorID = "truecordis";
    const cUserID = "json4289test";
    const cPassword = "json4289nodtst";

    // First check to see if the incoming response json is valid json
    // next, for the received iRequestID or or cControlNumber, do a lookup in your database to see if the order exists
    // If so return success (if the creds are also valid)

    // For now just hard code these vars until attached to the back end.
    const lValidJSON = true;
    const lRequestFound = true;
    const lControlNumberFound = true;

    // Next, compare what we have received vs what we SHOULD receive.
    
    let cMessage = "";

    if(!lValidJSON) {
        cMessage = "Response is not valid JSON.";
        iCode = -1;  // JSON is not valid
    } else if(cVendorID  != gjBody.tcinterface.confirm.cVendorID ||
            cUserID   != gjBody.tcinterface.confirm.cUserID ||
            cPassword != gjBody.tcinterface.confirm.cPassword ) {

        cMessage = "Credentials are not valid.";
        iCode = -2;  // Creds are not what they are supposed to be
                      
    } else if(!lRequestFound || !lControlNumberFound) {
        cMessage = "Request or control number not found.";
        iCode = -3; // Request or control number not found
    } else {
        cMessage = "Successfully received and processed JSON.";
        iCode = 0; // valid response!!!
    }

    // ENDBACKEND 

    let responseResult = {};

    // define some vars that are extracted from the response
    let iRequestID = gjBody.tcinterface.confirm.iRequestID
    let cControlNumber = gjBody.tcinterface.confirm.cControlNumber
    // If all is well, generate the response confirm result, either as a success a one of 3 or more failures 
    // as defined in the docs, Appendix 8
    // the following can be generated on the back end and not here... wherever works better for you
    console.log('iCode = ',iCode);
    if(iCode==0) {

        responseResult = {"tcinterface":
            {"iCode":iCode,
            "cMessage":cMessage,
            "cVendorID":gjBody.tcinterface.confirm.cVendorID,
            "cUserID":gjBody.tcinterface.confirm.cUserID,
            "cPassword":gjBody.tcinterface.confirm.cPassword,
            "iRequestID":iRequestID,
            "cControlNumber":cControlNumber}}

    } else if(iCode==-1) {
        responseResult = {"tcinterface":
            {"iCode":iCode,
            "cMessage":cMessage}}

        } else if(iCode==-2) {
        responseResult = {"tcinterface":
            {"iCode":iCode,
            "cMessage":cMessage,
            "cVendorID":gjBody.tcinterface.confirm.cVendorID,
            "cUserID":gjBody.tcinterface.confirm.cUserID,
            "cPassword":gjBody.tcinterface.confirm.cPassword}}

        } else if(iCode==-3) {
            responseResult = {"tcinterface":
            {"iCode":iCode,
            "cMessage":cMessage,
            "cVendorID":gjBody.tcinterface.confirm.cVendorID,
            "cUserID":gjBody.tcinterface.confirm.cUserID,
            "cPassword":gjBody.tcinterface.confirm.cPassword,
            "iRequestID":iRequestID,
            "cControlNumber":cControlNumber}}
        }

    // Finally display and write out the response confirm result    
    console.log('responseResult = ',responseResult);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.write(JSON.stringify(responseResult));
    res.end();
    console.log('RECEIVER app post Console log of what you sent me: ', req.body);
    console.log('RECEIVER app post of what is returned to the TC Connect response system: ', responseResult);
    console.log('END OF RESPONSE PROCESSING===================================');
    return;
});
