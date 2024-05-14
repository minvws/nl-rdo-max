window.onload = function funLoad() {
    bsn_input_listener()
    document.getElementById('bsn_inp').onchange = bsn_input_listener
}

function bsn_input_listener() {
    submitButton = document.getElementById("submit_two")
    relayState = submitButton.getAttribute("relaystate")
    bsn = document.getElementById("bsn_inp").value
    samlArt = submitButton.getAttribute("samlart")
    href = 'digid-mock-catch?bsn=' + bsn + '&SAMLart=' + samlArt + '&RelayState=' + relayState
    submitButton.href = href
}
