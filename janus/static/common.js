function send(command, data) {
    var detail = {
        command: command,
        bubbles: true
    };
    if (typeof data !== "undefined") {
        detail.data = data;
    }
    // TODO: FirefoxAccountsCommands, now it's WebChannelMessageToChrome
    // https://github.com/mozilla/fxa-content-server/blob/master/docs/relier-communication-protocols/fx-webchannel.md
    var event = new window.CustomEvent("FirefoxAccountsCommand", {
        detail: detail
    });
    window.dispatchEvent(event);
}

document.addEventListener("DOMContentLoaded", function() {
   send('loaded');
});
