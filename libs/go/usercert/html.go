// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package usercert

import (
	"fmt"
	"strings"
)

// closeWindowHTML returns the HTML page served on the /close endpoint after a
// successful IdP callback. When closeDelaySeconds > 0 the page shows a live
// countdown and attempts to close its own tab via window.close() when the
// countdown reaches zero; otherwise it shows a static "You may close this
// window now" message. window.close() is best-effort: some browsers only
// honor it for script-opened tabs, in which case the countdown message simply
// remains on screen.
func closeWindowHTML(closeDelaySeconds int) string {
	closeMsg := "You may close this window now."
	closeScript := ""
	if closeDelaySeconds > 0 {
		unit := "seconds"
		if closeDelaySeconds == 1 {
			unit = "second"
		}
		closeMsg = fmt.Sprintf("This window will close in %d %s.", closeDelaySeconds, unit)
		closeScript = fmt.Sprintf(closeWindowScriptTemplate, closeDelaySeconds)
	}
	return strings.NewReplacer(
		"__CLOSE_MSG__", closeMsg,
		"__CLOSE_SCRIPT__", closeScript,
	).Replace(closeWindowHTMLTemplate)
}

const closeWindowScriptTemplate = `  <script>
    (function() {
      var secs = %d;
      var el = document.getElementById('close-msg');
      var iv = setInterval(function() {
        secs--;
        if (secs <= 0) {
          clearInterval(iv);
          el.textContent = 'You may close this window now.';
          window.close();
        } else {
          el.textContent = 'This window will close in ' + secs + ' second' + (secs === 1 ? '' : 's') + '.';
        }
      }, 1000);
    })();
  </script>
`

const closeWindowHTMLTemplate = `<!DOCTYPE html>
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
    <span class="small-text" id="close-msg">__CLOSE_MSG__</span>
  </div>
__CLOSE_SCRIPT__</body>
</html>`
