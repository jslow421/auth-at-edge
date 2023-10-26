"use strict";
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const querystring = require("querystring");
const cookie = require("cookie");
const axios = require("axios");

const USERPOOLID = "us-east-1_rGFZUdHwc";
const CLIENT_ID = "5kj65h22fl3l0be5svgiec7490";
const OAUTH_TOKEN_URL =
  "https://slowiktest.auth.us-east-1.amazoncognito.com/oauth2/token";
const HOMEPAGE_URL = "https://ds060nnoq0vli.cloudfront.net/index.html";
const REDIRECT_URI = "https://ds060nnoq0vli.cloudfront.net/";

/**
 * Verifier for Cognito JWT tokens
 */
const verifier = CognitoJwtVerifier.create({
  userPoolId: USERPOOLID,
  tokenUse: "id",
  clientId: CLIENT_ID,
});

/**
 * Response to redirect the user to the Cognito login page
 */
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

/**
 * Get token from Cognito using the authorization code
 * @param {*} code
 * @returns
 */
async function exchangeCodeForToken(code) {
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
    const resData = resp.data;
    console.log("Response successful");

    return resData;
  } catch (error) {
    console.error("Error fetching tokens from Cognito:", error);
    console.log(error.data);
    callback(null, redirectToLogin);
    throw new Error("Error fetching tokens from Cognito");
  }
}

/**
 * Get the token from the request headers and validate it
 * @param {*} headers
 * @returns
 */
async function validateToken(headers) {
  let cookie_header = false;
  let jwtToken = "";
  if (headers.cookie) {
    let cookieArray = headers.cookie[0].value.split(";");
    console.log("Cookie array:");
    console.log(cookieArray);

    cookieArray.forEach((cookie) => {
      let cookieParts = cookie.split("=");

      if (cookieParts[0].trim().toLowerCase() === "authorization") {
        console.log("Found authorization cookie");
        jwtToken = cookieParts[1];
      }
    });

    cookie_header = true;
  }
  if (!cookie_header) {
    return false;
  }

  return await verifier.verify(jwtToken);
}

/**
 * Create a valid request with a specific cookie value
 * @param {*} setCookieValue
 * @returns
 */
function validRequestFactory(setCookieValue) {
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

  return validRequest;
}

/**
 * Lambda function handler
 * @param {*} event
 * @param {*} context
 * @param {*} callback
 * @returns
 */
exports.handler = async (event, context, callback) => {
  let setCookieValue = null;
  const cfrequest = event.Records[0].cf.request;
  const headers = cfrequest.headers;
  console.log("Function starting...");

  const { code } = querystring.parse(cfrequest.querystring);
  // Check if code is present in the request query string
  if (code?.length) {
    let response = await exchangeCodeForToken(code);

    setCookieValue = cookie.serialize("authorization", response.id_token, {
      maxAge: response.expires_in,
      path: "/",
      secure: false,
      httpOnly: false,
    });

    const validRequest = validRequestFactory(setCookieValue);

    callback(null, validRequest);
  }

  let result = null;
  try {
    result = await validateToken(headers);
  } catch (e) {
    // No cookie present
    callback(null, redirectToLogin);
  }

  if (!result) {
    console.log("Invalid access token");
    callback(null, redirectToLogin);
  }

  console.log("Valid access token found. Proceeding with request to origin.");

  return cfrequest;
};
