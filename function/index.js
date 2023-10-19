"use strict";
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const querystring = require("querystring");
const cookie = require("cookie");
const axios = require("axios");

const USERPOOLID = "us-east-1_rGFZUdHwc";
const REGION = "us-east-1";
const CLIENT_ID = "5kj65h22fl3l0be5svgiec7490";
const OAUTH_TOKEN_URL =
  "https://slowiktest.auth.us-east-1.amazoncognito.com/oauth2/token";
const HOMEPAGE_URL = "https://ds060nnoq0vli.cloudfront.net/index.html";
const REDIRECT_URI = "https://ds060nnoq0vli.cloudfront.net/";

// Verifier that expects valid access tokens:
const verifier = CognitoJwtVerifier.create({
  userPoolId: USERPOOLID,
  tokenUse: "id",
  clientId: CLIENT_ID,
});

const redirectToLogin = {
  status: "302",
  statusDescription: "Found",
  headers: {
    location: [
      {
        key: "Location",
        value:
          "https://slowiktest.auth.us-east-1.amazoncognito.com/login?response_type=code&client_id=5kj65h22fl3l0be5svgiec7490&redirect_uri=https://ds060nnoq0vli.cloudfront.net/",
      },
    ],
  },
};

// Function handler code
exports.handler = async (event, context, callback) => {
  let setCookieValue = null;
  console.log(event.Records[0]);
  console.log(event.Records[0].cf);
  console.log(event.Records[0].cf.request);
  const cfrequest = event.Records[0].cf.request;
  const cfresponse = event.Records[0].cf.response;
  const headers = cfrequest.headers;
  console.log("getting started");
  console.log("USERPOOLID=" + USERPOOLID);
  console.log("region=" + REGION);
  console.log("headers...");
  console.log(headers);
  console.log("response...");
  console.log(cfresponse);

  const { code } = querystring.parse(cfrequest.querystring);
  // Check if code is present in the request query string
  if (code && code.length > 0) {
    console.log("code in request url");

    // Create a data object with the necessary parameters
    const data = new URLSearchParams();
    data.append("grant_type", "authorization_code");
    data.append("client_id", CLIENT_ID);
    data.append("code", code);
    data.append("redirect_uri", REDIRECT_URI);

    const axiosConfig = {
      method: "post",
      url: OAUTH_TOKEN_URL,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: data,
    };

    try {
      const resp = await axios(axiosConfig);
      const resData = resp.data; // Assuming response contains JSON data
      console.log("Response successful");
      console.log(resData);
      setCookieValue = cookie.serialize("authorization", resData.id_token, {
        maxAge: resData.expires_in,
        path: "/",
        secure: false,
        httpOnly: false,
      });
    } catch (error) {
      console.error("Error fetching tokens from Cognito:", error);
      console.log(error.data);
      callback(null, redirectToLogin);
      throw new Error("Error fetching tokens from Cognito");
    }

    const validRequest = {
      status: "302",
      method: "GET",
      querystring: "",
      headers: {
        location: [
          {
            // instructs browser to redirect after receiving the response
            key: "Location",
            value: HOMEPAGE_URL,
          },
        ],
        "set-cookie": [
          {
            // instructs browser to store a cookie
            key: "Set-Cookie",
            value: setCookieValue,
          },
        ],
        "cache-control": [
          {
            // ensures that CloudFront does not cache the response
            key: "Cache-Control",
            value: "no-cache",
          },
        ],
      },
    };

    callback(null, validRequest);
  }

  //Fail if no authorization header found
  let auth_header = false;
  let cookie_header = false;
  let jwtToken = "";
  if (headers.authorization) {
    //strip out "Bearer " to extract JWT token only
    jwtToken = headers.authorization[0].value.slice(7);
    auth_header = true;
  } else if (headers.cookie) {
    let cookieArray = headers.cookie[0].value.split(";");
    console.log("Cookie array:");
    console.log(cookieArray);

    cookieArray.forEach(function (cookie) {
      console.log(cookie);
      let cookieParts = cookie.split("=");
      console.log("cookieParts:");
      console.log(cookieParts);

      if (cookieParts[0].trim().toLowerCase() === "authorization") {
        console.log("Found authorization cookie");
        console.log(cookieParts[1]);
        jwtToken = cookieParts[1];
      }
    });

    cookie_header = true;
  }
  if (!(cookie_header || auth_header)) {
    console.log("No auth header or cookie header found. Directing to login.");
    callback(null, redirectToLogin);
    return false;
  }

  //console.log("jwtToken= " + jwtToken);

  const result = await verifier.verify(jwtToken);

  if (!result) {
    console.log("Invalid access token");
    callback(null, redirectToLogin);

    return false;
  }
  console.log("Valid access token found. Proceeding with request to origin.");

  return cfrequest;
};
