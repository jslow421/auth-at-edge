"use strict";
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const querystring = require("querystring");
const cookie = require("cookie");
const axios = require("axios");
const readFileSync = require("fs").readFileSync;

const config = JSON.parse(readFileSync("config.json"));

let USERPOOLID,
  CLIENT_ID,
  COGNITO_HOSTED_UI_URL,
  OAUTH_TOKEN_URL,
  HOMEPAGE_URL,
  REDIRECT_URI;

async function getParametersFromSSM() {
  USERPOOLID = config.USERPOOLID;
  CLIENT_ID = config.CLIENT_ID;
  COGNITO_HOSTED_UI_URL = config.COGNITO_HOSTED_UI_URL;
  OAUTH_TOKEN_URL = config.OAUTH_TOKEN_URL;
  HOMEPAGE_URL = config.HOMEPAGE_URL;
  REDIRECT_URI = config.REDIRECT_URI;
}

/**
 * Generate login redirect response
 * @returns Login redirect response
 */
function loginRedirectFactory() {
  return {
    status: "302",
    statusDescription: "Found",
    headers: {
      location: [
        {
          key: "Location",
          value:
            COGNITO_HOSTED_UI_URL +
            "/login?response_type=code&client_id=" +
            CLIENT_ID +
            "&redirect_uri=" +
            REDIRECT_URI,
        },
      ],
    },
  };
}

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
    callback(null, loginRedirectFactory());
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

  const verifier = CognitoJwtVerifier.create({
    userPoolId: USERPOOLID,
    tokenUse: "id",
    clientId: CLIENT_ID,
  });

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
  await getParametersFromSSM();
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
    callback(null, loginRedirectFactory());
  }

  if (!result) {
    console.log("Invalid access token");
    callback(null, loginRedirectFactory());
  }

  console.log("Valid access token found. Proceeding with request to origin.");

  return cfrequest;
};
