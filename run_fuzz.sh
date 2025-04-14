#!/bin/bash

notify() {
	aws sns publish --topic-arn "arn:aws:sns:us-west-1:503561422289:fuzz_notify" --subject "Process Notification"  --message "Process ended" 
}

notify_phone() {
	aws sns publish --phone-number "+14806954145" --subject "Process Notification"  --message "Process ended" 
}

# set a trap to catch termination signals and send a notification
trap 'notify; exit 1' SIGINT SIGTERM
#trap 'notify_phone; exit 1' SIGINT SIGTERM

./civetweb_custom_fuzz fuzztest/http1

notify
#notify_phone

