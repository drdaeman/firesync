function send(command, data, messageId) {
    // https://github.com/mozilla/fxa-content-server/blob/master/docs/relier-communication-protocols/fx-webchannel.md
    if (!messageId) {
        messageId = new Date().getTime().toString(36) + "-" + Math.random().toString(36).substr(2);
    }
    var detail = {
        id: "account_updates",
        message: {
            command: command,
            messageId: messageId
        }
    };
    if (typeof data !== "undefined") {
        detail.message.data = data;
    }
    var ua = navigator.userAgent,
        uaFxIndex = ua.indexOf("Firefox/"),
        uaFxVersion = uaFxIndex >= 0 ? ua.substr(uaFxIndex + 8) : null;
    if (uaFxVersion !== null) {
        var i = uaFxVersion.indexOf(" ");
        if (i > 0) {
            uaFxVersion = uaFxVersion.substr(0, i);
        }
        try {
            uaFxVersion = parseFloat(uaFxVersion);
        } catch (e) {
            uaFxVersion = null;
        }
    }

    var event = new window.CustomEvent("WebChannelMessageToChrome", {
        detail: (uaFxVersion === null || uaFxVersion >= 50) ? JSON.stringify(detail) : detail
    });
    window.dispatchEvent(event);
}

document.addEventListener("DOMContentLoaded", function() {
   send('fxaccounts:loaded');
});
