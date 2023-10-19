"use strict";
var jwt = require("jsonwebtoken");
var jwkToPem = require("jwk-to-pem");

/*
TO DO:
copy values from CloudFormation outputs into USERPOOLID and JWKS variables
*/

var USERPOOLID = "us-east-1_zcKxhUnEB";
/*
JWKS found at https://cognito-idp.us-east-1.amazonaws.com/us-east-1_zcKxhUnEB/.well-known/jwks.json && https://www.googleapis.com/oauth2/v3/certs
*/
var JWKS =
  '{"keys":[{"alg":"RS256","e":"AQAB","kid":"zrwjSngPq8fyCvqWp9Lmk1tZSZdF7bHTA5cO3GGI54E=","kty":"RSA","n":"wSo0L57cy5yScPilUQ7tibEpAJf0RywFdBTJD1GQLkTsJoqzwDic-x0kTnP71bZWpO0r2Z4Ezd8_qfGrduHzSJHsvWzvO0RS_cKyRoCzS5bKSxHdKhX78hMNKZTrlTdBJTT7_fnf8QJSZ-x-G9u3zdcWEBscm-DcngloLWYjmo4jfTV8c-tZ-PmDMz3enVLD9_62VNTRjcT70_lO-5wVbyBbhdMT039bxycYETdOQ-SnYbNgqRPBF1nzRFjN68y6-ukrpg8DT-gNsQoKAO5GYSUi-YGDal14EQ_remZyjYbK0_AiEt4odx7S5sdXQt9Kck9jJP0JTakzcY3WkKIDZw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"RLN7xVCXzQ2Gif30yw5kOu4rIVS/485q2pSQmKx6zTE=","kty":"RSA","n":"1BL4XsXCR5faW_5L5PrNP3yYPTYtn3Cw2Fpsb-mnjqThYlIVA-_IIY5aNesM0arTSGmIUKz0pnNM79D93cxKi_4M3UqqITfw-YlKutkn7mi9OUtg_0hvJSGN4juEOOJFP9QGxalN0v5h25fNY6ykO9DGCelQz8zSqrIF_ohcNWYKHAnM1B5FCDK15wVUlMJ8iBdwE9z0tyOTtzPnUpXRNOc3m38UfLZf27bvkVD_EdDviyrFdExYnbS4Ava5uUPpPSDfkG--xcsYsvlmx6XbzaYWyF77W2cFuMK4_8jbcuyq7DhY0VtB3gq5ySpfwYiRkUNyt4B7Pj1qO7aSd8mm1w","use":"sig"}]}';
var GOOGLE_JWKS =
  '{"keys": [{"alg": "RS256","n": "q2RykXnOgOcHPG53sxgBmG9_TDuHVHeNjCaaKanxukluJUlKSIfcazMBeNhEPIdZvq61vPh9B4sY1Pv_pr0eAQu3r0_KnhktTaUaNrKGCIuawSJUNkK79Z-2npOEaOauKyNXuGXq_yHQI2U_61s2hjLntIjhtqABpizTkmSRtbx5KD9h3CGQ4CQVl795QZJwvSOVLNCM_uR1MMLPv-2aNKoNUs2v_0LZbYaIWTqScUXPY3aJ47XnmBzKcQtH4Fhx9oXFHuNtaw2fvIy14vhWDgLGtdCfeyllVEQHvyMzMdJCg59Qeh8cZSFsu2mktSG-Ak2Kr8pIYW2g1AL4oPQ4vw","use": "sig","kid": "183923c8cfec10f92cb013d06e1e7cdd7874aea5","kty": "RSA","e": "AQAB"},{"kty": "RSA","kid": "552de27f515737539600d89b9ee2e4ed535fb519","use": "sig","e": "AQAB","n": "v5R2bTIzHmvj1-GRBmn7CmyYKmyAbgPlKYonHe7OzrGDQKbpWHoedSzIxxWhAdeYsJlbQi53x7FbkhPxqFejvwpCjSrCdNQSBKyzHj0oWw2qpE3d7ELWFr_kEhapJAgkwHyCkLY5PsOqsCkRh8MQclP7bqf3-USlnpByIJ6RHJmdvW0QGwNIz-jHJI0QmK-kObgxQmZOIn0fyMNGTb86O5GzOV-3Qg3zneFYrV5TO_3Y4WEMBXhunOPJ_3bNaeO0dGeBnrW-VvNlU_eJECNqszIKY7DaUofW_yM-3wtAP3x3BF8P4UeZM8XQwgLKqDwYVtEzKXelv4iSdDtXVvbVYQ","alg": "RS256"}]}';
var region = "us-east-1";

/*
verify values above
*/

var iss_array = [
  "https://cognito-idp." + region + ".amazonaws.com/" + USERPOOLID,
  "https://accounts.google.com",
];
var pems;

pems = {};
var keys = JSON.parse(JWKS).keys.concat(JSON.parse(GOOGLE_JWKS).keys);
for (var i = 0; i < keys.length; i++) {
  //Convert each key to PEM
  var key_id = keys[i].kid;
  var modulus = keys[i].n;
  var exponent = keys[i].e;
  var key_type = keys[i].kty;
  var jwk = { kty: key_type, n: modulus, e: exponent };
  var pem = jwkToPem(jwk);
  pems[key_id] = pem;
}

const response401 = {
  status: "401",
  statusDescription: "Unauthorized",
};

const redirectToLogin = {
  status: "302",
  statusDescription: "Found",
  headers: {
    location: [
      {
        key: "Location",
        value:
          "https://auth.shell.caylent.com/oauth2/signin?client_id=3j89lpqpjrqonccvcar1mh1mf2&scope=openid&response_type=code&redirect_uri=https%3A%2F%2Fwww.shell-dev.caylent.dev%2Fapi%2Fauth%2Fcallback%2Fcognito&state=JVxH-sUf_aQmi3Czk9P_qjOITlvb-jBc3ke37uBzQjE",
      },
    ],
  },
};

exports.handler = (event, context, callback) => {
  console.log(event.Records[0]);
  console.log(event.Records[0].cf);
  console.log(event.Records[0].cf.request);
  const cfrequest = event.Records[0].cf.request;
  const headers = cfrequest.headers;
  console.log("getting started");
  console.log("USERPOOLID=" + USERPOOLID);
  console.log("region=" + region);
  console.log("pems=" + JSON.stringify(pems));
  console.log(headers);

  //Fail if no authorization header found
  var auth_header = false;
  var cookie_header = false;
  var jwtToken = "";
  if (headers.authorization) {
    //strip out "Bearer " to extract JWT token only
    jwtToken = headers.authorization[0].value.slice(7);
    auth_header = true;
  } else if (headers.cookie) {
    var cookieArray = headers.cookie[0].value.split(";");
    cookieArray.forEach(function (cookie) {
      console.log(cookie);
      var cookieParts = cookie.split("=");
      if (
        cookieParts[0].trim() == "Authorization" ||
        cookieParts[0].trim() == "authorization"
      ) {
        // jwtToken = cookieParts[1].slice(9); // 9 instead of 7 to account for %20
        jwtToken = cookieParts[1];
      }
    });
    cookie_header = true;
  }
  if (!(cookie_header || auth_header)) {
    console.log("no auth header or cookie header");
    // callback(null, response401);
    callback(null, redirectToLogin);
    return false;
  }

  console.log("jwtToken=" + jwtToken);

  //Fail if the token is not jwt
  var decodedJwt = jwt.decode(jwtToken, { complete: true });
  console.log(decodedJwt);
  if (!decodedJwt) {
    console.log("Not a valid JWT token");
    // callback(null, response401);
    callback(null, redirectToLogin);
    return false;
  }

  //Fail if token is not from your UserPool
  if (!iss_array.includes(decodedJwt.payload.iss)) {
    console.log("invalid issuer");
    callback(null, response401);
    return false;
  }

  //Reject the jwt if it's not an 'Access Token'
  // if (decodedJwt.payload.token_use != 'access') {
  //     console.log("Not an access token");
  //     callback(null, response401);
  //     return false;
  // }

  //Get the kid from the token and retrieve corresponding PEM
  var kid = decodedJwt.header.kid;
  var pem = pems[kid];
  if (!pem) {
    console.log("Invalid access token");
    callback(null, response401);
    return false;
  }

  //Verify the signature of the JWT token to ensure it's really coming from your User Pool
  jwt.verify(
    jwtToken,
    pem,
    { issuer: decodedJwt.payload.iss },
    function (err, payload) {
      if (err) {
        console.log("Token failed verification");
        // callback(null, response401);
        callback(null, redirectToLogin);
        return false;
      } else {
        //Valid token.
        console.log("Successful verification");
        //remove authorization header
        delete cfrequest.headers.authorization;
        //CloudFront can proceed to fetch the content from origin
        callback(null, cfrequest);
        return true;
      }
    }
  );
};
