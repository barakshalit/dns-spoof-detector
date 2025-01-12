#!/bin/bash

PROFILE_DIR=$(find ~/.mozilla/firefox -maxdepth 1 -type d -name "*.default-release")
USER_JS="$PROFILE_DIR/user.js"

cat <<EOL > "$USER_JS"
// Disable Telemetry
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);

// Disable Health Reports
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);

// Disable Studies
user_pref("app.shield.optoutstudies.enabled", false);

// Disable Crash Reporter
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

// Disable Experiments
user_pref("experiments.enabled", false);
user_pref("network.allow-experiments", false);

// Disable Recommendations
user_pref("browser.discovery.enabled", false);
EOL

echo "Telemetry and data collection preferences updated in $USER_JS."