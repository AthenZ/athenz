// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package usercert

const closeWindowHTML = `<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      display: flex;
      justify-content: center;
      margin: 0;
    }

    .message-box {
      border: 0.125em solid purple;
      padding: 1em;
      margin: 1.25em 0;
      font-family: Arial, sans-serif;
      color: #333;
      background-color: #f9f4ff;
      border-radius: 0.5em;
      display: table;
      width: 90%;
      max-width: 50em;
      box-sizing: border-box;
      text-align: center;
      font-size: 1.25em;
      line-height: 1.4;
    }

    .small-text {
      font-size: 0.75em;
      display: block;
      margin-top: 0.25em;
    }

  </style>
</head>
<body>
  <div class="message-box">
    <b>Authentication successful.</b><br>
    <span class="small-text">You may close this window now.</span>
  </div>
</body>
</html>`
