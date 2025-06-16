window.onload = function funLoad() {
    kvk_input_listener()
    document.getElementById('kvk_inp').onchange = kvk_input_listener
}

function kvk_input_listener() {
    submitButton = document.getElementById("submit_two")
    relayState = submitButton.getAttribute("relaystate")
    kvk = document.getElementById("kvk_inp").value
    samlArt = submitButton.getAttribute("samlart")
    href = 'eherkenning-mock-catch?kvk=' + kvk + '&SAMLart=' + samlArt + '&RelayState=' + relayState
    submitButton.href = href
}
